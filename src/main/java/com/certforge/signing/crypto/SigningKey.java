package com.certforge.signing.crypto;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Holds a private key and its certificate chain.
 * The private key remains token-backed and never leaves the PKCS#11 device.
 */
public class SigningKey {
    private final PrivateKey privateKey;
    private final X509Certificate[] certificateChain;

    public SigningKey(PrivateKey privateKey, X509Certificate[] certificateChain) {
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate[] getCertificateChain() {
        return certificateChain;
    }
}