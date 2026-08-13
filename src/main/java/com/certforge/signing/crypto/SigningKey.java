package com.certforge.signing.crypto;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Holds a private key and its certificate chain.
 * The private key remains token-backed and never leaves the PKCS#11 device.
 */
public record SigningKey(PrivateKey privateKey, X509Certificate[] certificateChain) {
}