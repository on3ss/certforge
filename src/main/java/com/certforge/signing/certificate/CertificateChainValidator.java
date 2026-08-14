package com.certforge.signing.certificate;

import com.certforge.audit.AuditLogger;
import com.certforge.signing.exception.InvalidCertificateException;

import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Validates a certificate chain for signing suitability.
 */
public class CertificateChainValidator {

    private static final Logger LOG = Logger.getLogger(CertificateChainValidator.class.getName());
    private final AuditLogger auditLogger;

    public CertificateChainValidator(AuditLogger auditLogger) {
        this.auditLogger = Objects.requireNonNull(auditLogger, "auditLogger cannot be null");
    }

    public void validate(X509Certificate[] chain) throws InvalidCertificateException {
        if (chain == null || chain.length == 0) {
            auditLogger.logError("certificate_validation", "Certificate chain is empty");
            throw new InvalidCertificateException("Certificate chain is empty");
        }

        X509Certificate leaf = chain[0];

        try {
            leaf.checkValidity();
        } catch (Exception e) {
            auditLogger.logError("certificate_validation",
                    "Certificate expired or not yet valid: " + leaf.getSubjectX500Principal().getName());
            throw new InvalidCertificateException("Certificate is not valid: " + e.getMessage());
        }

        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && keyUsage.length > 0 && !keyUsage[0]) {
            auditLogger.logError("certificate_validation",
                    "Certificate does not allow digital signatures: " + leaf.getSubjectX500Principal().getName());
            throw new InvalidCertificateException("Certificate does not allow digital signatures");
        }

        String algorithm = leaf.getPublicKey().getAlgorithm();
        if (!"RSA".equals(algorithm) && !"EC".equals(algorithm)) {
            auditLogger.logError("certificate_validation",
                    "Unsupported key algorithm: " + algorithm);
            throw new InvalidCertificateException("Unsupported key algorithm: " + algorithm);
        }

        LOG.fine(() -> "Certificate chain validated for subject: " + leaf.getSubjectX500Principal().getName());
    }
}