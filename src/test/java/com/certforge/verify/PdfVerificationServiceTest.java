package com.certforge.verify;

import com.certforge.audit.AuditLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PdfVerificationServiceTest {

    @TempDir
    Path tempDir;

    private PdfVerificationService verificationService;

    @BeforeEach
    void setUp() {
        AuditLogger auditLogger = new AuditLogger(tempDir.resolve("audit.log"));
        verificationService = new PdfVerificationService(auditLogger);
    }

    @Test
    void shouldReturnNoSignaturesForUnsignedPdf() {
        // Create a minimal PDF (no signatures)
        byte[] unsignedPdf = "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF".getBytes();

        VerificationResult result = verificationService.verify(unsignedPdf);

        assertFalse(result.valid());
        assertTrue(result.signatures().isEmpty());
    }

    @Test
    void shouldHandleCorruptedPdf() {
        byte[] corruptedPdf = "not a pdf".getBytes();

        VerificationResult result = verificationService.verify(corruptedPdf);

        assertFalse(result.valid());
    }
}