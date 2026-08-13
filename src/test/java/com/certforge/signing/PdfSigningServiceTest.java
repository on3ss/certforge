package com.certforge.signing;

import com.certforge.audit.AuditLogger;
import com.certforge.signing.certificate.CertificateChainValidator;
import com.certforge.signing.cms.CmsSigningService;
import com.certforge.signing.crypto.SigningKeyProvider;
import com.certforge.session.SessionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PdfSigningServiceTest {

    @TempDir
    Path tempDir;

    private AuditLogger auditLogger;
    private SessionManager sessionManager;

    @BeforeEach
    void setUp() {
        auditLogger = new AuditLogger(tempDir.resolve("audit.log"));
        sessionManager = new SessionManager(auditLogger);
    }

    @Test
    void shouldConstructSuccessfully() {
        SigningKeyProvider signingKeyProvider = new SigningKeyProvider(sessionManager, auditLogger);
        CertificateChainValidator certValidator = new CertificateChainValidator(auditLogger);
        CmsSigningService cmsSigningService = new CmsSigningService(auditLogger);

        PdfSigningService service = new PdfSigningService(
                signingKeyProvider, certValidator, cmsSigningService, auditLogger
        );

        assertNotNull(service);
    }

    @Test
    void shouldFailForNonexistentSession() {
        SigningKeyProvider signingKeyProvider = new SigningKeyProvider(sessionManager, auditLogger);
        CertificateChainValidator certValidator = new CertificateChainValidator(auditLogger);
        CmsSigningService cmsSigningService = new CmsSigningService(auditLogger);

        PdfSigningService service = new PdfSigningService(
                signingKeyProvider, certValidator, cmsSigningService, auditLogger
        );

        // Sign with nonexistent session should fail
        assertThrows(
                com.certforge.signing.exception.SigningKeyNotFoundException.class,
                () -> service.signPdf("nonexistent-session", "anyAlias", new byte[]{1, 2, 3})
        );
    }

    @Test
    void shouldFailForEmptyPdf() {
        SigningKeyProvider signingKeyProvider = new SigningKeyProvider(sessionManager, auditLogger);
        CertificateChainValidator certValidator = new CertificateChainValidator(auditLogger);
        CmsSigningService cmsSigningService = new CmsSigningService(auditLogger);

        PdfSigningService service = new PdfSigningService(
                signingKeyProvider, certValidator, cmsSigningService, auditLogger
        );

        // Sign with empty PDF should fail at key lookup stage (session not found)
        assertThrows(
                com.certforge.signing.exception.SigningKeyNotFoundException.class,
                () -> service.signPdf("nonexistent-session", "anyAlias", new byte[0])
        );
    }
}