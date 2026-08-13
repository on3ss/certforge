package com.certforge.session;

import com.certforge.discovery.TokenInfo;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class SessionManager {

    private static final Logger LOG = Logger.getLogger(SessionManager.class.getName());

    private final Map<String, SessionData> sessions = new ConcurrentHashMap<>();

    /**
     * Opens a session to the given token using the PIN.
     */
    public String openSession(TokenInfo token, String pin) throws Exception {
        String config = "--name=CertForge-" + token.getId() + "\n" +
                "library=" + token.getLibraryPath() + "\n" +
                "slot=" + token.getSlotId() + "\n";

        LOG.fine(() -> "Configuring SunPKCS11 provider for token slot " + token.getSlotId());
        Provider provider = Security.getProvider("SunPKCS11");
        if (provider != null) {
            provider = provider.configure(config);
        } else {
            provider = new sun.security.pkcs11.SunPKCS11().configure(config);
        }
        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance("PKCS11", provider);
        ks.load(null, pin.toCharArray());

        String sessionId = UUID.randomUUID().toString().replace("-", "");
        sessions.put(sessionId, new SessionData(token, provider, ks, pin));

        LOG.info("Session opened: " + sessionId + " for token " + token.getLabel());
        return sessionId;
    }

    /**
     * Lists certificates available on the token for the given session.
     */
    public List<CertificateInfo> listCertificates(String sessionId) throws Exception {
        SessionData session = getSession(sessionId);
        List<CertificateInfo> certificates = new ArrayList<>();

        LOG.fine(() -> "Listing certificates for session " + sessionId + " (KeyStore type: " + session.keyStore.getType() + ")");

        Enumeration<String> aliases = session.keyStore.aliases();
        int aliasCount = 0;

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            aliasCount++;
            LOG.fine(() -> "Examining alias: '" + alias + "'");

            X509Certificate cert = null;

            if (session.keyStore.isCertificateEntry(alias)) {
                cert = (X509Certificate) session.keyStore.getCertificate(alias);
                LOG.fine(() -> "Found certificate entry for alias: " + alias);
            } else if (session.keyStore.isKeyEntry(alias)) {
                cert = (X509Certificate) session.keyStore.getCertificate(alias);
                LOG.fine(() -> "Found key entry certificate for alias: " + alias);
            }

            if (cert != null) {
                String subject = cert.getSubjectX500Principal().getName();
                String issuer = cert.getIssuerX500Principal().getName();
                String serialNumber = cert.getSerialNumber().toString(16);
                String notBefore = cert.getNotBefore().toInstant().toString();
                String notAfter = cert.getNotAfter().toInstant().toString();

                String keyType = "Unknown";
                int keySize = 0;
                if (cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey rsaKey) {
                    keyType = "RSA";
                    keySize = rsaKey.getModulus().bitLength();
                } else if (cert.getPublicKey() instanceof java.security.interfaces.ECPublicKey ecKey) {
                    keyType = "EC";
                    keySize = ecKey.getParams().getCurve().getField().getFieldSize();
                }

                certificates.add(new CertificateInfo(
                        alias, subject, issuer, serialNumber,
                        notBefore, notAfter, keyType, keySize
                ));
                LOG.fine(() -> "Added certificate: alias=" + alias + ", subject=" + subject);
            }
        }

        final int totalAliases = aliasCount;
        LOG.fine(() -> "Enumerated " + totalAliases + " alias(es), returning " + certificates.size() + " certificate(s) for session " + sessionId);

        return certificates;
    }

    /**
     * Gets the KeyStore for a session (used for signing operations).
     */
    public KeyStore getKeyStore(String sessionId) throws Exception {
        return getSession(sessionId).keyStore;
    }

    /**
     * Gets the token associated with a session.
     */
    public TokenInfo getToken(String sessionId) throws Exception {
        return getSession(sessionId).token;
    }

    /**
     * Closes a session and releases resources.
     */
    public void closeSession(String sessionId) {
        SessionData session = sessions.remove(sessionId);
        if (session != null) {
            try {
                Security.removeProvider(session.provider.getName());
                // Zero out PIN
                Arrays.fill(session.pin.toCharArray(), '0');
            } catch (Exception e) {
                LOG.fine("Exception while removing provider for session " + sessionId + ": " + e.getMessage());
            }
            LOG.info("Session closed: " + sessionId);
        } else {
            LOG.fine("Attempted to close non-existent session: " + sessionId);
        }
    }

    /**
     * Checks if a session exists.
     */
    public boolean sessionExists(String sessionId) {
        return sessions.containsKey(sessionId);
    }

    private SessionData getSession(String sessionId) throws Exception {
        SessionData session = sessions.get(sessionId);
        if (session == null) {
            throw new Exception("Session not found: " + sessionId);
        }
        return session;
    }

    private static class SessionData {
        final TokenInfo token;
        final Provider provider;
        final KeyStore keyStore;
        final String pin;

        SessionData(TokenInfo token, Provider provider, KeyStore keyStore, String pin) {
            this.token = token;
            this.provider = provider;
            this.keyStore = keyStore;
            this.pin = pin;
        }
    }
}
