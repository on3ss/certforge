package com.certforge.signing.crypto;

import com.certforge.signing.exception.TokenSigningException;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Pkcs11CryptoSigner implements CryptoSigner {

    private static final Logger LOG = Logger.getLogger(Pkcs11CryptoSigner.class.getName());

    private final PrivateKey privateKey;
    private final X509Certificate[] certificateChain;
    private final Provider pkcs11Provider;
    private final String signatureAlgorithm;

    public Pkcs11CryptoSigner(PrivateKey privateKey,
                              X509Certificate[] certificateChain,
                              Provider pkcs11Provider,
                              String signatureAlgorithm) {
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
        this.pkcs11Provider = pkcs11Provider;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public byte[] sign(byte[] data) throws TokenSigningException {
        try {
            LOG.fine(() -> "PKCS#11 signing " + data.length + " bytes using " + signatureAlgorithm
                    + " with provider " + pkcs11Provider.getName()
                    + " (" + privateKey.getAlgorithm() + " key)");

            Signature signature = Signature.getInstance(signatureAlgorithm, pkcs11Provider);
            signature.initSign(privateKey);
            signature.update(data);
            byte[] signatureBytes = signature.sign();

            LOG.fine(() -> "PKCS#11 signature generated: " + signatureBytes.length + " bytes");
            return signatureBytes;

        } catch (Exception e) {
            LOG.log(Level.SEVERE, "PKCS#11 signing failed: " + e.getMessage(), e);
            throw new TokenSigningException(
                    "Token rejected the signing operation: " + e.getMessage(), e);
        }
    }

    @Override
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    @Override
    public X509Certificate[] getCertificateChain() {
        return certificateChain;
    }
}