// certificate/CertificateChainValidator.java
package com.certforge.signing.certificate;

import com.certforge.signing.exception.InvalidCertificateException;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.logging.Logger;

/**
 * Validates a certificate chain for signing suitability.
 */
public class CertificateChainValidator {

    private static final Logger LOG = Logger.getLogger(CertificateChainValidator.class.getName());

    public void validate(X509Certificate[] chain) throws InvalidCertificateException {
        if (chain == null || chain.length == 0) {
            throw new InvalidCertificateException("Certificate chain is empty");
        }

        X509Certificate leaf = chain[0];

        // Check validity period
        try {
            leaf.checkValidity();
        } catch (Exception e) {
            throw new InvalidCertificateException("Certificate is not valid: " + e.getMessage());
        }

        // Check key usage (digitalSignature bit)
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && keyUsage.length > 0 && !keyUsage[0]) {
            throw new InvalidCertificateException("Certificate does not allow digital signatures");
        }

        // Check algorithm
        String algorithm = leaf.getPublicKey().getAlgorithm();
        if (!"RSA".equals(algorithm) && !"EC".equals(algorithm)) {
            throw new InvalidCertificateException("Unsupported key algorithm: " + algorithm);
        }

        LOG.fine("Certificate chain validated: " + leaf.getSubjectX500Principal().getName());
    }
}