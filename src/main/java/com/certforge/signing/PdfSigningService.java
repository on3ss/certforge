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

    @Override
    public byte[] signPdf(String sessionId, String alias, byte[] pdfBytes)
            throws PdfSigningException, SigningKeyNotFoundException, InvalidCertificateException {
        LOG.info("Starting PDF signing with alias: " + alias);
        LOG.fine(() -> "PDF input size: " + pdfBytes.length + " bytes");

        // 1. Get signing key
        SigningKey signingKey = signingKeyProvider.getSigningKey(sessionId, alias);
        X509Certificate[] chain = signingKey.certificateChain();

        // 2. Validate certificate chain
        certificateValidator.validate(chain);

        // 3. Create crypto signer
        CryptoSigner cryptoSigner = new Pkcs11CryptoSigner(
                signingKey.privateKey(),
                chain,
                signingKeyProvider.getProvider(sessionId),
                determineSignatureAlgorithm(chain[0]),
                auditLogger
        );

        // 4. Sign PDF using external signing flow
        try (PDDocument document = Loader.loadPDF(pdfBytes)) {
            // Create signature dictionary
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName(alias);
            signature.setSignDate(Calendar.getInstance());
            signature.setReason("CertForge Digital Signature");
            signature.setLocation("Local Gateway");

            // Signature options
            SignatureOptions options = new SignatureOptions();
            options.setPreferredSignatureSize(32768);

            // Add signature to document
            document.addSignature(signature, options);

            // Prepare for external signing
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            ExternalSigningSupport externalSigning =
                    document.saveIncrementalForExternalSigning(output);

            // Get the exact byte range to sign
            byte[] cmsSignature;
            try (InputStream content = externalSigning.getContent()) {
                byte[] contentBytes = content.readAllBytes();
                LOG.fine(() -> "PDF content to sign: " + contentBytes.length + " bytes");

                // Create CMS signature
                cmsSignature = cmsSigningService.createDetachedSignature(
                        contentBytes, cryptoSigner);
                LOG.fine(() -> "CMS signature size: " + cmsSignature.length + " bytes");
            }

            // Set the CMS signature
            externalSigning.setSignature(cmsSignature);

            byte[] signedPdf = output.toByteArray();
            LOG.info("PDF successfully signed. Final size: " + signedPdf.length + " bytes");

            // Verify signature was embedded
            verifySignedPdf(signedPdf);

            // Audit: document signed successfully
            auditLogger.logDocumentSigned(
                    sessionId, alias, "success", pdfBytes.length, cmsSignature.length
            );

            return signedPdf;

        } catch (PdfSigningException e) {
            LOG.log(Level.SEVERE, "PDF signing failed for alias " + alias + ": " + e.getMessage(), e);

            // Audit: signing failed
            auditLogger.logSigningFailed(sessionId, alias, e.getMessage());

            throw e;
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "PDF signing failed for alias " + alias + ": " + e.getMessage(), e);

            // Audit: signing failed
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
}