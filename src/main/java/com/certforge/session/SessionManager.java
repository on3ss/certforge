package com.certforge.session;

import com.certforge.audit.AuditLogger;
import com.certforge.discovery.TokenInfo;
import com.certforge.pool.Pkcs11SessionPool;
import com.certforge.pool.PoolConfig;
import com.certforge.pool.PooledSession;
import com.certforge.pool.SunPkcs11SessionFactory;

import java.security.KeyStore;
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

    private final Map<String, PooledSession> activeSessions = new ConcurrentHashMap<>();
    private final AuditLogger auditLogger;
    private final Pkcs11SessionPool pool;
    private final int inactivityTimeoutSeconds;
    private final int maxLifetimeSeconds;
    private final ScheduledExecutorService cleanupExecutor;

    public SessionManager(AuditLogger auditLogger) {
        this(auditLogger, PoolConfig.defaultConfig(), 3600, 86400);
    }

    public SessionManager(AuditLogger auditLogger, int inactivityTimeoutSeconds, int maxLifetimeSeconds) {
        this(auditLogger, PoolConfig.defaultConfig(), inactivityTimeoutSeconds, maxLifetimeSeconds);
    }

    public SessionManager(AuditLogger auditLogger, PoolConfig poolConfig) {
        this(auditLogger, poolConfig, 3600, 86400);
    }

    public SessionManager(AuditLogger auditLogger, PoolConfig poolConfig, int inactivityTimeoutSeconds, int maxLifetimeSeconds) {
        this(auditLogger, new Pkcs11SessionPool(poolConfig, new SunPkcs11SessionFactory(), auditLogger), inactivityTimeoutSeconds, maxLifetimeSeconds);
    }

    public SessionManager(AuditLogger auditLogger, Pkcs11SessionPool pool, int inactivityTimeoutSeconds, int maxLifetimeSeconds) {
        this.auditLogger = auditLogger;
        this.pool = pool;
        this.inactivityTimeoutSeconds = inactivityTimeoutSeconds;
        this.maxLifetimeSeconds = maxLifetimeSeconds;
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "session-cleanup");
            t.setDaemon(true);
            return t;
        });

        this.cleanupExecutor.scheduleAtFixedRate(
                this::cleanupExpiredSessions,
                60, 60, TimeUnit.SECONDS
        );

        LOG.info("SessionManager initialized: inactivityTimeout=" + inactivityTimeoutSeconds +
                "s, maxLifetime=" + maxLifetimeSeconds + "s");
    }

    /**
     * Opens a session to the given token using the PIN, borrowing from pool.
     */
    public String openSession(TokenInfo token, String pin) throws Exception {
        PooledSession session = pool.borrow(token, pin);
        String sessionId = session.id();
        activeSessions.put(sessionId, session);

        if (auditLogger != null) {
            auditLogger.logPoolBorrow(sessionId, token.id());
            auditLogger.logSessionOpened(sessionId, token.id());
        }
        LOG.info("Session opened: " + sessionId + " for token " + token.id());
        return sessionId;
    }

    /**
     * Lists certificates — also refreshes last activity.
     */
    public List<CertificateInfo> listCertificates(String sessionId) throws Exception {
        PooledSession session = getSession(sessionId);
        session.touch(Instant.now());
        List<CertificateInfo> certificates = new ArrayList<>();

        Enumeration<String> aliases = session.keyStore().aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = null;

            if (session.keyStore().isCertificateEntry(alias)) {
                cert = (X509Certificate) session.keyStore().getCertificate(alias);
            } else if (session.keyStore().isKeyEntry(alias)) {
                cert = (X509Certificate) session.keyStore().getCertificate(alias);
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
        PooledSession session = getSession(sessionId);
        session.touch(Instant.now());
        return session.keyStore();
    }

    /**
     * Gets the token — also refreshes last activity.
     */
    public TokenInfo getToken(String sessionId) throws Exception {
        PooledSession session = getSession(sessionId);
        session.touch(Instant.now());
        return session.token();
    }

    /**
     * Closes a session and returns it to the pool.
     */
    public void closeSession(String sessionId) {
        PooledSession session = activeSessions.remove(sessionId);
        if (session != null) {
            pool.returnSession(session);
            if (auditLogger != null) {
                auditLogger.logPoolReturn(sessionId, session.token().id());
                auditLogger.logSessionClosed(sessionId, session.token().id());
            }
            LOG.info("Session closed: " + sessionId);
        }
    }

    /**
     * Checks if a session exists and is not expired.
     */
    public boolean sessionExists(String sessionId) {
        PooledSession session = activeSessions.get(sessionId);
        if (session == null) return false;
        return !isExpired(session, Instant.now());
    }

    /**
     * Shuts down the cleanup executor and session pool.
     */
    public void shutdown() {
        cleanupExecutor.shutdown();
        pool.shutdown();
        LOG.info("SessionManager shutdown");
    }

    /**
     * Periodic cleanup of expired sessions.
     */
    private void cleanupExpiredSessions() {
        Instant now = Instant.now();
        int expiredCount = 0;

        for (Map.Entry<String, PooledSession> entry : activeSessions.entrySet()) {
            if (isExpired(entry.getValue(), now)) {
                String sessionId = entry.getKey();
                closeSession(sessionId);
                if (auditLogger != null) {
                    auditLogger.logSessionExpired(sessionId);
                }
                expiredCount++;
            }
        }

        if (expiredCount > 0) {
            LOG.info("Cleaned up " + expiredCount + " expired session(s)");
        }
    }

    private boolean isExpired(PooledSession session, Instant now) {
        if (!session.isValid()) {
            return true;
        }
        if (session.createdAt().plusSeconds(maxLifetimeSeconds).isBefore(now)) {
            return true;
        }
        if (session.lastUsed().plusSeconds(inactivityTimeoutSeconds).isBefore(now)) {
            return true;
        }
        return false;
    }

    private PooledSession getSession(String sessionId) throws Exception {
        PooledSession session = activeSessions.get(sessionId);
        if (session == null) {
            if (auditLogger != null) {
                auditLogger.logSessionNotFound(sessionId);
            }
            throw new Exception("Session not found: " + sessionId);
        }

        if (isExpired(session, Instant.now())) {
            closeSession(sessionId);
            if (auditLogger != null) {
                auditLogger.logSessionExpired(sessionId);
            }
            throw new Exception("Session expired: " + sessionId);
        }

        return session;
    }
}