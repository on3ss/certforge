package com.certforge.signing.crypto;

import com.certforge.audit.AuditLogger;
import com.certforge.session.SessionManager;
import com.certforge.signing.exception.SigningKeyNotFoundException;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Retrieves signing keys from an active session.
 * Separated from PDF signing logic.
 */
public class SigningKeyProvider {

    private static final Logger LOG = Logger.getLogger(SigningKeyProvider.class.getName());

    private final SessionManager sessionManager;
    private final AuditLogger auditLogger;

    public SigningKeyProvider(SessionManager sessionManager, AuditLogger auditLogger) {
        this.sessionManager = Objects.requireNonNull(sessionManager, "sessionManager cannot be null");
        this.auditLogger = Objects.requireNonNull(auditLogger, "auditLogger cannot be null");
    }

    /**
     * Gets the signing key for the given alias from the session.
     * The private key remains token-backed.
     */
    public SigningKey getSigningKey(String sessionId, String alias) throws SigningKeyNotFoundException {
        try {
            KeyStore keyStore = sessionManager.getKeyStore(sessionId);
            Provider provider = keyStore.getProvider();

            if (!keyStore.containsAlias(alias)) {
                auditLogger.logError("signing_key_retrieval", "Alias not found on token: " + alias);
                throw new SigningKeyNotFoundException("Alias not found on token: " + alias);
            }

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            if (privateKey == null) {
                auditLogger.logError("signing_key_retrieval", "No private key for alias: " + alias);
                throw new SigningKeyNotFoundException("No private key for alias: " + alias);
            }

            var certChain = keyStore.getCertificateChain(alias);
            if (certChain == null || certChain.length == 0) {
                auditLogger.logError("signing_key_retrieval", "No certificate chain for alias: " + alias);
                throw new SigningKeyNotFoundException("No certificate chain for alias: " + alias);
            }

            X509Certificate[] chain = Arrays.stream(certChain)
                    .map(cert -> (X509Certificate) cert)
                    .toArray(X509Certificate[]::new);

            LOG.fine(() -> "Signing key retrieved for alias: " + alias);
            return new SigningKey(privateKey, chain);

        } catch (SigningKeyNotFoundException e) {
            throw e;
        } catch (Exception e) {
            auditLogger.logError("signing_key_retrieval",
                    "Failed to retrieve signing key for alias " + alias + ": " + e.getMessage());
            throw new SigningKeyNotFoundException("Failed to retrieve signing key: " + e.getMessage());
        }
    }

    /**
     * Gets the PKCS#11 provider from the session.
     * Used by Pkcs11CryptoSigner for explicit provider control.
     */
    public Provider getProvider(String sessionId) throws SigningKeyNotFoundException {
        try {
            return sessionManager.getKeyStore(sessionId).getProvider();
        } catch (Exception e) {
            auditLogger.logError("signing_key_retrieval",
                    "Failed to get provider for session " + sessionId + ": " + e.getMessage());
            throw new SigningKeyNotFoundException("Session not found: " + e.getMessage());
        }
    }
}