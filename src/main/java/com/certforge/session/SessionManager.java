package com.certforge.session;

import com.certforge.audit.AuditEventType;
import com.certforge.audit.AuditLogger;
import com.certforge.discovery.TokenInfo;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class SessionManager {

    private static final Logger LOG = Logger.getLogger(SessionManager.class.getName());

    private final Map<String, SessionData> sessions = new ConcurrentHashMap<>();
    private final AuditLogger auditLogger;
    private final int inactivityTimeoutSeconds;
    private final int maxLifetimeSeconds;
    private final ScheduledExecutorService cleanupExecutor;

    public SessionManager(AuditLogger auditLogger) {
        this(auditLogger, 3600, 86400); // Defaults: 1h inactivity, 24h max
    }

    public SessionManager(AuditLogger auditLogger, int inactivityTimeoutSeconds, int maxLifetimeSeconds) {
        this.auditLogger = auditLogger;
        this.inactivityTimeoutSeconds = inactivityTimeoutSeconds;
        this.maxLifetimeSeconds = maxLifetimeSeconds;
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "session-cleanup");
            t.setDaemon(true);
            return t;
        });

        // Schedule cleanup every 60 seconds
        this.cleanupExecutor.scheduleAtFixedRate(
                this::cleanupExpiredSessions,
                60, 60, TimeUnit.SECONDS
        );

        LOG.info("SessionManager initialized: inactivityTimeout=" + inactivityTimeoutSeconds +
                "s, maxLifetime=" + maxLifetimeSeconds + "s");
    }

    /**
     * Opens a session to the given token using the PIN.
     */
    public String openSession(TokenInfo token, String pin) throws Exception {
        String config = "--name=CertForge-" + token.id() + "\n" +
                "library=" + token.libraryPath() + "\n" +
                "slot=" + token.slotId() + "\n";

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
        Instant now = Instant.now();
        sessions.put(sessionId, new SessionData(token, provider, ks, pin, now, now));

        auditLogger.logSessionOpened(sessionId, token.id());
        LOG.info("Session opened: " + sessionId + " for token " + token.id());
        return sessionId;
    }

    /**
     * Lists certificates — also refreshes last activity.
     */
    public List<CertificateInfo> listCertificates(String sessionId) throws Exception {
        SessionData session = getSession(sessionId);
        session.touch(); // Refresh activity
        List<CertificateInfo> certificates = new ArrayList<>();

        Enumeration<String> aliases = session.keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = null;

            if (session.keyStore.isCertificateEntry(alias)) {
                cert = (X509Certificate) session.keyStore.getCertificate(alias);
            } else if (session.keyStore.isKeyEntry(alias)) {
                cert = (X509Certificate) session.keyStore.getCertificate(alias);
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
            }
        }
        return certificates;
    }

    /**
     * Gets the KeyStore — also refreshes last activity.
     */
    public KeyStore getKeyStore(String sessionId) throws Exception {
        SessionData session = getSession(sessionId);
        session.touch();
        return session.keyStore;
    }

    /**
     * Gets the token — also refreshes last activity.
     */
    public TokenInfo getToken(String sessionId) throws Exception {
        SessionData session = getSession(sessionId);
        session.touch();
        return session.token;
    }

    /**
     * Closes a session and releases resources.
     */
    public void closeSession(String sessionId) {
        SessionData session = sessions.remove(sessionId);
        if (session != null) {
            try {
                Security.removeProvider(session.provider.getName());
                Arrays.fill(session.pin.toCharArray(), '0');
            } catch (Exception e) {
                LOG.fine("Exception removing provider: " + e.getMessage());
            }
            auditLogger.logSessionClosed(sessionId, session.token.id());
            LOG.info("Session closed: " + sessionId);
        }
    }

    /**
     * Checks if a session exists and is not expired.
     */
    public boolean sessionExists(String sessionId) {
        SessionData session = sessions.get(sessionId);
        if (session == null) return false;
        return !isExpired(session, Instant.now());
    }

    /**
     * Shuts down the cleanup executor.
     */
    public void shutdown() {
        cleanupExecutor.shutdown();
        LOG.info("SessionManager shutdown");
    }

    /**
     * Periodic cleanup of expired sessions.
     */
    private void cleanupExpiredSessions() {
        Instant now = Instant.now();
        int expiredCount = 0;

        for (Map.Entry<String, SessionData> entry : sessions.entrySet()) {
            if (isExpired(entry.getValue(), now)) {
                String sessionId = entry.getKey();
                closeSession(sessionId);
                auditLogger.logSessionExpired(sessionId);
                expiredCount++;
            }
        }

        if (expiredCount > 0) {
            LOG.info("Cleaned up " + expiredCount + " expired session(s)");
        }
    }

    private boolean isExpired(SessionData session, Instant now) {
        // Check max lifetime
        if (session.createdAt.plusSeconds(maxLifetimeSeconds).isBefore(now)) {
            return true;
        }
        // Check inactivity
        if (session.lastActivity.plusSeconds(inactivityTimeoutSeconds).isBefore(now)) {
            return true;
        }
        return false;
    }

    private SessionData getSession(String sessionId) throws Exception {
        SessionData session = sessions.get(sessionId);
        if (session == null) {
            auditLogger.logSessionNotFound(sessionId);
            throw new Exception("Session not found: " + sessionId);
        }

        // Check expiry
        if (isExpired(session, Instant.now())) {
            closeSession(sessionId);
            auditLogger.logSessionExpired(sessionId);
            throw new Exception("Session expired: " + sessionId);
        }

        return session;
    }

    private static class SessionData {
        final TokenInfo token;
        final Provider provider;
        final KeyStore keyStore;
        final String pin;
        final Instant createdAt;
        volatile Instant lastActivity;

        SessionData(TokenInfo token, Provider provider, KeyStore keyStore, String pin,
                    Instant createdAt, Instant lastActivity) {
            this.token = token;
            this.provider = provider;
            this.keyStore = keyStore;
            this.pin = pin;
            this.createdAt = createdAt;
            this.lastActivity = lastActivity;
        }

        void touch() {
            this.lastActivity = Instant.now();
        }
    }
}