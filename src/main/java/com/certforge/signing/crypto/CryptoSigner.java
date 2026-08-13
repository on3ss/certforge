package com.certforge.signing.crypto;

import com.certforge.signing.exception.TokenSigningException;

import java.security.cert.X509Certificate;

/**
 * Abstraction for cryptographic signing operations.
 * Implementations can be PKCS#11, remote, HSM, or mock.
 */
public interface CryptoSigner {

    /**
     * Signs the given data.
     *
     * @param data data to sign (typically a PDF byte range hash)
     * @return signature bytes
     * @throws TokenSigningException if signing fails
     */
    byte[] sign(byte[] data) throws TokenSigningException;

    /**
     * Gets the signature algorithm name (e.g., "SHA256withRSA").
     */
    String getSignatureAlgorithm();

    /**
     * Gets the certificate chain for this signer.
     * Chain is ordered leaf → intermediate → root.
     */
    X509Certificate[] getCertificateChain();
}