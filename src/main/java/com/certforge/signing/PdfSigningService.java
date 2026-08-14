package com.certforge.signing;

import com.certforge.audit.AuditLogger;
import com.certforge.signing.certificate.CertificateChainValidator;
import com.certforge.signing.cms.CmsSigningService;
import com.certforge.signing.crypto.CryptoSigner;
import com.certforge.signing.crypto.Pkcs11CryptoSigner;
import com.certforge.signing.crypto.SigningKey;
import com.certforge.signing.crypto.SigningKeyProvider;
import com.certforge.signing.exception.InvalidCertificateException;
import com.certforge.signing.exception.PdfSigningException;
import com.certforge.signing.exception.SigningKeyNotFoundException;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PdfSigningService implements SigningService {

    private static final Logger LOG = Logger.getLogger(PdfSigningService.class.getName());

    private final SigningKeyProvider signingKeyProvider;
    private final CertificateChainValidator certificateValidator;
    private final CmsSigningService cmsSigningService;
    private final AuditLogger auditLogger;

    public PdfSigningService(SigningKeyProvider signingKeyProvider,
                             CertificateChainValidator certificateValidator,
                             CmsSigningService cmsSigningService,
                             AuditLogger auditLogger) {
        this.signingKeyProvider = Objects.requireNonNull(signingKeyProvider, "signingKeyProvider cannot be null");
        this.certificateValidator = Objects.requireNonNull(certificateValidator, "certificateValidator cannot be null");
        this.cmsSigningService = Objects.requireNonNull(cmsSigningService, "cmsSigningService cannot be null");
        this.auditLogger = Objects.requireNonNull(auditLogger, "auditLogger cannot be null");
    }

    public byte[] signPdfWithAppearance(String sessionId, String alias, byte[] pdfBytes,
                                        com.certforge.signing.appearance.SignatureAppearance appearance)
            throws PdfSigningException, SigningKeyNotFoundException, InvalidCertificateException {
        return signPdf(sessionId, alias, pdfBytes, appearance);
    }

    @Override
    public byte[] signPdf(String sessionId, String alias, byte[] pdfBytes, com.certforge.signing.appearance.SignatureAppearance appearance)
            throws PdfSigningException, SigningKeyNotFoundException, InvalidCertificateException {
        LOG.info("Starting PDF signing with alias: " + alias + (appearance != null ? " (visible appearance type=" + appearance.type() + ")" : ""));
        LOG.fine(() -> "PDF input size: " + pdfBytes.length + " bytes");

        SigningKey signingKey = signingKeyProvider.getSigningKey(sessionId, alias);
        X509Certificate[] chain = signingKey.certificateChain();

        certificateValidator.validate(chain);

        CryptoSigner cryptoSigner = new Pkcs11CryptoSigner(
                signingKey.privateKey(),
                chain,
                signingKeyProvider.getProvider(sessionId),
                determineSignatureAlgorithm(chain[0]),
                auditLogger
        );

        try (PDDocument document = Loader.loadPDF(pdfBytes)) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName(alias);
            signature.setSignDate(Calendar.getInstance());
            signature.setReason("CertForge Digital Signature");
            signature.setLocation("Local Gateway");

            SignatureOptions options = new SignatureOptions();
            options.setPreferredSignatureSize(32768);

            if (appearance != null && appearance.type() != com.certforge.signing.appearance.SignatureAppearance.Type.NONE) {
                int totalPages = document.getNumberOfPages();
                int pageIdx = Math.min(Math.max(0, appearance.page()), Math.max(0, totalPages - 1));

                org.apache.pdfbox.pdmodel.common.PDRectangle pBBox = null;
                if (appearance.getSearchText() != null && !appearance.getSearchText().isBlank()) {
                    TextSearchResult searchResult = findTextInDocument(document, appearance);
                    if (searchResult != null) {
                        pageIdx = searchResult.pageIndex();
                        pBBox = searchResult.rectangle();
                    } else {
                        LOG.warning("Search text '" + appearance.getSearchText() + "' not found in PDF. Falling back to page position / absolute coordinates.");
                    }
                }

                options.setPage(pageIdx);

                var page = document.getPage(pageIdx);
                if (pBBox == null) {
                    pBBox = resolveRectangle(page, appearance);
                }
                float[] rect = new float[] { pBBox.getLowerLeftX(), pBBox.getLowerLeftY(), pBBox.getWidth(), pBBox.getHeight() };

                InputStream visStream = com.certforge.signing.appearance.AppearanceStreamBuilder.buildVisualSignatureStream(
                        appearance, rect[0], rect[1], rect[2], rect[3]
                );
                if (visStream != null) {
                    options.setVisualSignature(visStream);
                }

                if (appearance.reason() != null && !appearance.reason().isBlank()) {
                    signature.setReason(appearance.reason());
                }
                if (appearance.location() != null && !appearance.location().isBlank()) {
                    signature.setLocation(appearance.location());
                }
            }

            document.addSignature(signature, options);

            ByteArrayOutputStream output = new ByteArrayOutputStream();
            ExternalSigningSupport externalSigning =
                    document.saveIncrementalForExternalSigning(output);

            byte[] cmsSignature;
            try (InputStream content = externalSigning.getContent()) {
                byte[] contentBytes = content.readAllBytes();
                LOG.fine(() -> "PDF content to sign: " + contentBytes.length + " bytes");

                cmsSignature = cmsSigningService.createDetachedSignature(
                        contentBytes, cryptoSigner);
                LOG.fine(() -> "CMS signature size: " + cmsSignature.length + " bytes");
            }

            externalSigning.setSignature(cmsSignature);

            byte[] signedPdf = output.toByteArray();
            LOG.info("PDF successfully signed. Final size: " + signedPdf.length + " bytes");

            verifySignedPdf(signedPdf);

            auditLogger.logDocumentSigned(
                    sessionId, alias, "success", pdfBytes.length, cmsSignature.length
            );

            return signedPdf;

        } catch (PdfSigningException e) {
            LOG.log(Level.SEVERE, "PDF signing failed for alias " + alias + ": " + e.getMessage(), e);
            auditLogger.logSigningFailed(sessionId, alias, e.getMessage());
            throw e;
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "PDF signing failed for alias " + alias + ": " + e.getMessage(), e);
            auditLogger.logSigningFailed(sessionId, alias, e.getMessage());

            throw new PdfSigningException("Failed to sign PDF", e);
        }
    }

    /**
     * Diagnostic method to verify the signed PDF contains a valid signature.
     */
    private void verifySignedPdf(byte[] signedPdf) {
        try (PDDocument signedDocument = Loader.loadPDF(signedPdf)) {
            List<PDSignature> signatures = signedDocument.getSignatureDictionaries();
            LOG.fine(() -> "Signatures found in signed PDF: " + signatures.size());

            for (PDSignature sig : signatures) {
                LOG.fine(() -> "  Signature name: " + sig.getName()
                        + ", SubFilter: " + sig.getSubFilter()
                        + ", Contents length: " + (sig.getContents() != null ? sig.getContents().length : "null")
                        + ", ByteRange: " + java.util.Arrays.toString(sig.getByteRange()));
            }
        } catch (Exception e) {
            LOG.warning("Failed to verify signed PDF: " + e.getMessage());
        }
    }

    private String determineSignatureAlgorithm(X509Certificate leaf) {
        String algorithm = leaf.getPublicKey().getAlgorithm();
        if ("EC".equals(algorithm)) {
            return "SHA256withECDSA";
        }
        return "SHA256withRSA";
    }

    public org.apache.pdfbox.pdmodel.common.PDRectangle resolveRectangle(
            org.apache.pdfbox.pdmodel.PDPage page,
            com.certforge.signing.appearance.SignatureAppearance appearance) {
        if (appearance.getPosition() != null || appearance.getPagePosition() != null) {
            var position = appearance.getPosition();
            var pageBox = page.getCropBox() != null ? page.getCropBox() : page.getMediaBox();
            float margin = 20f;
            float width = Math.min(appearance.getWidth(), pageBox.getWidth() - 2 * margin);
            float height = Math.min(appearance.getHeight(), pageBox.getHeight() - 2 * margin);
            float x = 0, y = 0;

            if (position != null) {
                switch (position) {
                    case TOP_LEFT -> {
                        x = margin;
                        y = pageBox.getHeight() - margin - height;
                    }
                    case TOP_RIGHT -> {
                        x = pageBox.getWidth() - margin - width;
                        y = pageBox.getHeight() - margin - height;
                    }
                    case BOTTOM_LEFT -> {
                        x = margin;
                        y = margin;
                    }
                    case BOTTOM_RIGHT -> {
                        x = pageBox.getWidth() - margin - width;
                        y = margin;
                    }
                    case CENTER -> {
                        x = (pageBox.getWidth() - width) / 2f;
                        y = (pageBox.getHeight() - height) / 2f;
                    }
                }
                return new org.apache.pdfbox.pdmodel.common.PDRectangle(x, y, width, height);
            }
        }
        return new org.apache.pdfbox.pdmodel.common.PDRectangle(
                appearance.getX(), appearance.getY(), appearance.getWidth(), appearance.getHeight()
        );
    }

    private record TextSearchResult(int pageIndex, org.apache.pdfbox.pdmodel.common.PDRectangle rectangle) {}

    private TextSearchResult findTextInDocument(PDDocument document, com.certforge.signing.appearance.SignatureAppearance appearance) {
        String searchText = appearance.getSearchText();
        if (searchText == null || searchText.isBlank()) return null;
        try {
            TextPositionFinder finder = new TextPositionFinder(searchText);
            finder.setStartPage(1);
            finder.setEndPage(document.getNumberOfPages());
            finder.getText(document);

            if (finder.getFoundPageIndex() >= 0) {
                int foundPage = finder.getFoundPageIndex();
                var page = document.getPage(foundPage);
                var pageBox = page.getCropBox() != null ? page.getCropBox() : page.getMediaBox();
                var rect = finder.getFoundRectangle(
                        pageBox.getWidth(), pageBox.getHeight(),
                        appearance.getWidth(), appearance.getHeight(),
                        appearance.searchPosition()
                );
                if (rect != null) {
                    LOG.info(() -> "Found search text '" + searchText + "' on page " + (foundPage + 1)
                            + " (0-based index " + foundPage + ") with searchPosition=" + appearance.searchPosition());
                    return new TextSearchResult(foundPage, rect);
                }
            }
            LOG.info(() -> "Search text '" + searchText + "' was not found on any page of the document.");
            return null;
        } catch (Exception e) {
            LOG.fine(() -> "Text search across document for '" + searchText + "' failed: " + e.getMessage());
            return null;
        }
    }

    private static class TextPositionFinder extends org.apache.pdfbox.text.PDFTextStripper {
        private final String searchText;
        private int foundPageIndex = -1;
        private float foundX = -1f;
        private float foundY = -1f;
        private float matchedTextWidth = 0f;
        private float matchedTextHeight = 12f;

        private final List<org.apache.pdfbox.text.TextPosition> pagePositions = new java.util.ArrayList<>();

        TextPositionFinder(String searchText) throws IOException {
            this.searchText = searchText;
            setSortByPosition(true);
        }

        @Override
        protected void processTextPosition(org.apache.pdfbox.text.TextPosition text) {
            if (text != null && text.getUnicode() != null && !text.getUnicode().isEmpty()) {
                pagePositions.add(text);
            }
            super.processTextPosition(text);
        }

        @Override
        protected void startPage(org.apache.pdfbox.pdmodel.PDPage page) throws IOException {
            pagePositions.clear();
            super.startPage(page);
        }

        @Override
        protected void endPage(org.apache.pdfbox.pdmodel.PDPage page) throws IOException {
            if (foundPageIndex == -1 && !pagePositions.isEmpty()) {
                findInPagePositions();
            }
            super.endPage(page);
        }

        private void findInPagePositions() {
            String target = searchText.replaceAll("\\s+", "").toLowerCase();
            if (target.isEmpty()) return;

            StringBuilder sb = new StringBuilder();
            int startIndex = -1;

            for (int i = 0; i < pagePositions.size(); i++) {
                org.apache.pdfbox.text.TextPosition tp = pagePositions.get(i);
                String unicode = tp.getUnicode();
                if (unicode == null || unicode.isEmpty()) continue;

                for (char c : unicode.toCharArray()) {
                    if (Character.isWhitespace(c)) continue;

                    if (sb.length() == 0) {
                        startIndex = i;
                    }
                    sb.append(Character.toLowerCase(c));

                    if (sb.toString().equals(target)) {
                        foundPageIndex = getCurrentPageNo() - 1;
                        org.apache.pdfbox.text.TextPosition matchTp = pagePositions.get(startIndex);
                        foundX = matchTp.getXDirAdj() != 0 ? matchTp.getXDirAdj() : matchTp.getX();
                        foundY = matchTp.getYDirAdj() != 0 ? matchTp.getYDirAdj() : matchTp.getY();

                        float widthSum = 0f;
                        float maxHeight = 12f;
                        for (int k = startIndex; k <= i && k < pagePositions.size(); k++) {
                            org.apache.pdfbox.text.TextPosition ptp = pagePositions.get(k);
                            widthSum += ptp.getWidthDirAdj() > 0 ? ptp.getWidthDirAdj() : ptp.getWidth();
                            if (ptp.getHeightDir() > maxHeight) maxHeight = ptp.getHeightDir();
                            if (ptp.getFontSizeInPt() > maxHeight) maxHeight = ptp.getFontSizeInPt();
                        }
                        matchedTextWidth = widthSum;
                        matchedTextHeight = maxHeight;

                        final float fx = foundX, fy = foundY, tw = matchedTextWidth, th = matchedTextHeight;
                        LOG.info(() -> "Matched search text! char=" + matchTp.getUnicode() + " foundX=" + fx + " foundY=" + fy + " textWidth=" + tw + " textHeight=" + th);
                        return;
                    }

                    if (!target.startsWith(sb.toString())) {
                        sb.setLength(0);
                        i = startIndex;
                        startIndex = -1;
                        break;
                    }
                }
            }
        }

        int getFoundPageIndex() {
            return foundPageIndex;
        }

        org.apache.pdfbox.pdmodel.common.PDRectangle getFoundRectangle(
                float pageWidth, float pageHeight, float width, float height,
                com.certforge.signing.appearance.SignatureAppearance.SearchPosition searchPosition) {
            if (foundX < 0 || foundY < 0) return null;

            float textPdfY = pageHeight - foundY;
            float textHeight = matchedTextHeight > 0 ? matchedTextHeight : 12f;
            float textWidth = matchedTextWidth > 0 ? matchedTextWidth : 100f;

            float marginOffset = 6f;
            float rawX = foundX;
            float rawY = textPdfY + marginOffset;

            com.certforge.signing.appearance.SignatureAppearance.SearchPosition pos =
                    searchPosition != null ? searchPosition : com.certforge.signing.appearance.SignatureAppearance.SearchPosition.ABOVE;

            switch (pos) {
                case ABOVE -> {
                    rawX = foundX;
                    rawY = textPdfY + marginOffset;
                }
                case BELOW -> {
                    rawX = foundX;
                    rawY = textPdfY - textHeight - height - marginOffset;
                }
                case LEFT -> {
                    rawX = foundX - width - marginOffset;
                    rawY = textPdfY - height + textHeight;
                }
                case RIGHT -> {
                    rawX = foundX + textWidth + marginOffset;
                    rawY = textPdfY - height + textHeight;
                }
                case OVER -> {
                    rawX = foundX;
                    rawY = textPdfY - height;
                }
            }

            float pageMargin = 15f;
            float clampedX = Math.min(rawX, pageWidth - width - pageMargin);
            clampedX = Math.max(pageMargin, clampedX);

            float clampedY = Math.min(rawY, pageHeight - height - pageMargin);
            clampedY = Math.max(pageMargin, clampedY);

            final float fRawX = rawX, fRawY = rawY, fClampedX = clampedX, fClampedY = clampedY;
            LOG.info(() -> String.format(
                    "Calculated signature box for searchPosition '%s': raw (%.1f, %.1f) -> clamped (%.1f, %.1f) [width=%.1f, height=%.1f, pageBounds=%.1fx%.1f]",
                    pos, fRawX, fRawY, fClampedX, fClampedY, width, height, pageWidth, pageHeight));

            return new org.apache.pdfbox.pdmodel.common.PDRectangle(clampedX, clampedY, width, height);
        }
    }
}