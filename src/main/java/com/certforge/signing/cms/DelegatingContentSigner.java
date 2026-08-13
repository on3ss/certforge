package com.certforge.signing.cms;

import com.certforge.signing.crypto.CryptoSigner;
import com.certforge.signing.exception.TokenSigningException;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

/**
 * ContentSigner that delegates the actual signing to a CryptoSigner.
 * This ensures the PKCS#11 provider is used for the signing operation.
 */
class DelegatingContentSigner implements ContentSigner {

    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    private final CryptoSigner cryptoSigner;
    private final AlgorithmIdentifier algorithmIdentifier;

    DelegatingContentSigner(String signatureAlgorithm, CryptoSigner cryptoSigner) {
        this.cryptoSigner = cryptoSigner;
        this.algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder()
                .find(signatureAlgorithm);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            return cryptoSigner.sign(outputStream.toByteArray());
        } catch (TokenSigningException e) {
            throw new RuntimeException("Signing failed", e);
        }
    }
}