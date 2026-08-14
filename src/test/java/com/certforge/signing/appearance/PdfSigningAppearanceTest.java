package com.certforge.signing.appearance;

import com.certforge.audit.AuditLogger;
import com.certforge.signing.PdfSigningService;
import com.certforge.signing.certificate.CertificateChainValidator;
import com.certforge.signing.cms.CmsSigningService;
import com.certforge.signing.crypto.CryptoSigner;
import com.certforge.signing.crypto.SigningKey;
import com.certforge.signing.crypto.SigningKeyProvider;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PdfSigningAppearanceTest {

    @TempDir
    Path tempDir;

    private AuditLogger auditLogger;

    @BeforeEach
    void setUp() {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        auditLogger = new AuditLogger(tempDir.resolve("audit.log"));
    }

    @Test
    void testBuildVisualSignatureStreamContainsAcroFormAndSignatureField() throws Exception {
        SignatureAppearance appearance = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .textLines(List.of("Digitally signed by CertForge Test", "Date: 2026-08-14"))
                .width(200f)
                .height(50f)
                .build();

        var stream = AppearanceStreamBuilder.buildVisualSignatureStream(appearance, 0f, 0f, 200f, 50f);
        assertNotNull(stream);

        byte[] templateBytes = stream.readAllBytes();
        assertTrue(templateBytes.length > 0);

        try (PDDocument doc = Loader.loadPDF(templateBytes)) {
            assertNotNull(doc.getDocumentCatalog().getAcroForm(), "Visual template PDF must contain an AcroForm");
            assertFalse(doc.getDocumentCatalog().getAcroForm().getFields().isEmpty(), "Visual template AcroForm must contain at least one field");
        }
    }

    @Test
    void testEndToEndVisualPdfSigning() throws Exception {
        // 1. Generate test RSA keypair and self-signed certificate
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        X509Certificate cert = generateTestCertificate(keyPair);

        // 2. Create test PDF document
        byte[] inputPdfBytes = createSamplePdf();

        // 3. Create dummy providers & services
        final SigningKey mockSigningKey = new SigningKey(keyPair.getPrivate(), new X509Certificate[]{cert});
        com.certforge.session.SessionManager sessionManager = new com.certforge.session.SessionManager(auditLogger);
        SigningKeyProvider mockKeyProvider = new SigningKeyProvider(sessionManager, auditLogger) {
            @Override
            public SigningKey getSigningKey(String sessionId, String alias) {
                return mockSigningKey;
            }

            @Override
            public Provider getProvider(String sessionId) {
                return java.security.Security.getProvider("BC");
            }
        };

        CertificateChainValidator mockValidator = new CertificateChainValidator(auditLogger) {
            @Override
            public void validate(X509Certificate[] chain) {
                // Skip CRL/OCSP check for test self-signed cert
            }
        };

        CmsSigningService cmsService = new CmsSigningService(auditLogger);
        PdfSigningService pdfSigningService = new PdfSigningService(mockKeyProvider, mockValidator, cmsService, auditLogger);

        // 4. Sign PDF with visible appearance
        SignatureAppearance appearance = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .page(0)
                .positionType(SignatureAppearance.PositionType.PAGE_POSITION)
                .pagePosition(SignatureAppearance.PagePosition.BOTTOM_RIGHT)
                .width(200f)
                .height(50f)
                .textLines(List.of("Signed by CertForge", "Reason: Integration Test"))
                .build();

        byte[] signedPdf = pdfSigningService.signPdf("test-session", "testAlias", inputPdfBytes, appearance);
        assertNotNull(signedPdf);
        assertTrue(signedPdf.length > inputPdfBytes.length);

        // 5. Verify signed PDF contains AcroForm and Signature Field
        try (PDDocument signedDoc = Loader.loadPDF(signedPdf)) {
            List<PDSignature> signatures = signedDoc.getSignatureDictionaries();
            assertEquals(1, signatures.size(), "Signed PDF must contain exactly 1 digital signature");
            assertEquals("testAlias", signatures.get(0).getName());
            assertNotNull(signedDoc.getDocumentCatalog().getAcroForm(), "Signed PDF must have an AcroForm");
        }
    }

    private byte[] createSamplePdf() throws Exception {
        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.LETTER);
            doc.addPage(page);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            return baos.toByteArray();
        }
    }

    private X509Certificate generateTestCertificate(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now - 1000 * 60 * 60);
        Date endDate = new Date(now + 1000L * 60 * 60 * 24 * 365);

        X500Name dnName = new X500Name("CN=CertForge Test Signer, O=CertForge, C=US");
        BigInteger certSerialNumber = BigInteger.valueOf(now);

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic()
        );

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    }

    @Test
    void testMultiPageDocumentTextSearchPositioning() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        X509Certificate cert = generateTestCertificate(keyPair);

        // Create 3-page PDF with "Treasury Officer" text on page 2 (index 1)
        byte[] multiPagePdf;
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage(PDRectangle.LETTER)); // Page 1

            PDPage page2 = new PDPage(PDRectangle.LETTER); // Page 2
            doc.addPage(page2);
            try (org.apache.pdfbox.pdmodel.PDPageContentStream cs = new org.apache.pdfbox.pdmodel.PDPageContentStream(doc, page2)) {
                cs.beginText();
                cs.setFont(new org.apache.pdfbox.pdmodel.font.PDType1Font(org.apache.pdfbox.pdmodel.font.Standard14Fonts.FontName.HELVETICA), 12);
                cs.newLineAtOffset(100, 400);
                cs.showText("Treasury Officer");
                cs.endText();
            }

            doc.addPage(new PDPage(PDRectangle.LETTER)); // Page 3

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            multiPagePdf = baos.toByteArray();
        }

        final SigningKey mockSigningKey = new SigningKey(keyPair.getPrivate(), new X509Certificate[]{cert});
        com.certforge.session.SessionManager sessionManager = new com.certforge.session.SessionManager(auditLogger);
        SigningKeyProvider mockKeyProvider = new SigningKeyProvider(sessionManager, auditLogger) {
            @Override
            public SigningKey getSigningKey(String sessionId, String alias) {
                return mockSigningKey;
            }

            @Override
            public Provider getProvider(String sessionId) {
                return java.security.Security.getProvider("BC");
            }
        };

        CertificateChainValidator mockValidator = new CertificateChainValidator(auditLogger) {
            @Override
            public void validate(X509Certificate[] chain) {}
        };

        CmsSigningService cmsService = new CmsSigningService(auditLogger);
        PdfSigningService pdfSigningService = new PdfSigningService(mockKeyProvider, mockValidator, cmsService, auditLogger);

        SignatureAppearance appearance = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .searchText("Treasury Officer")
                .width(200f)
                .height(45f)
                .textLines(List.of("Digitally Signed Here", "Status: Approved"))
                .build();

        byte[] signedPdf = pdfSigningService.signPdf("test-session", "testAlias", multiPagePdf, appearance);
        assertNotNull(signedPdf);

        try (PDDocument signedDoc = Loader.loadPDF(signedPdf)) {
            List<PDSignature> signatures = signedDoc.getSignatureDictionaries();
            assertEquals(1, signatures.size());
            var widget = signedDoc.getSignatureFields().get(0).getWidgets().get(0);
            assertNotNull(widget);
            assertEquals(signedDoc.getPage(1), widget.getPage(), "Signature widget must be placed on Page 2 where 'Treasury Officer' text was found");
        }
    }

    @Test
    void testTopRightTextSearchPositioningWithCaseAndSpacingVariations() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        X509Certificate cert = generateTestCertificate(keyPair);

        byte[] pdfWithTopRightText;
        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.LETTER); // 612 x 792
            doc.addPage(page);
            try (org.apache.pdfbox.pdmodel.PDPageContentStream cs = new org.apache.pdfbox.pdmodel.PDPageContentStream(doc, page)) {
                cs.beginText();
                cs.setFont(new org.apache.pdfbox.pdmodel.font.PDType1Font(org.apache.pdfbox.pdmodel.font.Standard14Fonts.FontName.HELVETICA), 12);
                cs.newLineAtOffset(450, 720); // Top Right corner
                cs.showText("Treasury   Officer"); // Extra spaces in PDF stream
                cs.endText();
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            pdfWithTopRightText = baos.toByteArray();
        }

        final SigningKey mockSigningKey = new SigningKey(keyPair.getPrivate(), new X509Certificate[]{cert});
        com.certforge.session.SessionManager sessionManager = new com.certforge.session.SessionManager(auditLogger);
        SigningKeyProvider mockKeyProvider = new SigningKeyProvider(sessionManager, auditLogger) {
            @Override
            public SigningKey getSigningKey(String sessionId, String alias) {
                return mockSigningKey;
            }

            @Override
            public Provider getProvider(String sessionId) {
                return java.security.Security.getProvider("BC");
            }
        };

        CertificateChainValidator mockValidator = new CertificateChainValidator(auditLogger) {
            @Override
            public void validate(X509Certificate[] chain) {}
        };

        CmsSigningService cmsService = new CmsSigningService(auditLogger);
        PdfSigningService pdfSigningService = new PdfSigningService(mockKeyProvider, mockValidator, cmsService, auditLogger);

        SignatureAppearance appearance = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .searchText("treasury officer") // Lowercase search term
                .width(150f)
                .height(40f)
                .textLines(List.of("Approved"))
                .build();

        byte[] signedPdf = pdfSigningService.signPdf("test-session", "testAlias", pdfWithTopRightText, appearance);
        assertNotNull(signedPdf);

        try (PDDocument signedDoc = Loader.loadPDF(signedPdf)) {
            var widget = signedDoc.getSignatureFields().get(0).getWidgets().get(0);
            assertNotNull(widget);
            var rect = widget.getRectangle();
            // 1. Must fit inside page width 612.0 without cutoff (clamped to page margin)
            assertTrue(rect.getLowerLeftX() + 150f <= 612f, "Signature widget must not be cutoff past right edge (x+w <= 612), found right edge: " + (rect.getLowerLeftX() + 150f));
            // 2. Must be positioned ABOVE search text baseline (y >= 720.0)
            assertTrue(rect.getLowerLeftY() >= 720f, "Signature widget must be positioned ABOVE search text (y >= 720), found: " + rect.getLowerLeftY());
        }
    }
}
