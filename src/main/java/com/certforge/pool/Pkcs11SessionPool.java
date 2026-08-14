package com.certforge.pool;

import com.certforge.audit.AuditLogger;
import com.certforge.discovery.TokenInfo;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.logging.Logger;

public class Pkcs11SessionPool {

    private static final Logger LOG = Logger.getLogger(Pkcs11SessionPool.class.getName());

    private final PoolConfig config;
    private final Pkcs11SessionFactory factory;
    private final AuditLogger auditLogger;
    private final Clock clock;
    private final Semaphore semaphore;
    private final Map<String, ConcurrentLinkedQueue<PooledSession>> idleQueues = new ConcurrentHashMap<>();
    private final ScheduledExecutorService evictionExecutor;
    private volatile boolean shutdown = false;

    public Pkcs11SessionPool(PoolConfig config, Pkcs11SessionFactory factory) {
        this(config, factory, null, Clock.systemUTC());
    }

    public Pkcs11SessionPool(PoolConfig config, Pkcs11SessionFactory factory, AuditLogger auditLogger) {
        this(config, factory, auditLogger, Clock.systemUTC());
    }

    public Pkcs11SessionPool(PoolConfig config, Pkcs11SessionFactory factory, AuditLogger auditLogger, Clock clock) {
        this.config = Objects.requireNonNull(config, "PoolConfig cannot be null");
        this.factory = Objects.requireNonNull(factory, "Pkcs11SessionFactory cannot be null");
        this.auditLogger = auditLogger;
        this.clock = Objects.requireNonNull(clock, "Clock cannot be null");
        this.semaphore = new Semaphore(config.maxTotal(), true);

        if (config.validationIntervalSeconds() > 0) {
            this.evictionExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "pkcs11-pool-evictor");
                t.setDaemon(true);
                return t;
            });
            this.evictionExecutor.scheduleAtFixedRate(
                    this::evictIdleSessions,
                    config.validationIntervalSeconds(),
                    config.validationIntervalSeconds(),
                    TimeUnit.SECONDS
            );
        } else {
            this.evictionExecutor = null;
        }

        LOG.info("Pkcs11SessionPool initialized: maxTotal=" + config.maxTotal() +
                ", maxIdle=" + config.maxIdle() +
                ", idleTimeout=" + config.idleTimeoutSeconds() + "s");
    }

    /**
     * Borrows a session from the pool for the given token.
     * Reuses an idle valid session if available; otherwise creates a new one subject to maxTotal.
     */
    public PooledSession borrow(TokenInfo token, String pin) throws Exception {
        if (shutdown) {
            throw new IllegalStateException("Session pool is shut down");
        }

        String tokenId = token.id();
        ConcurrentLinkedQueue<PooledSession> queue = idleQueues.get(tokenId);

        if (queue != null) {
            PooledSession idleSession;
            while ((idleSession = queue.poll()) != null) {
                final PooledSession candidate = idleSession;
                if (isValidAndNotExpired(candidate)) {
                    candidate.touch(clock.instant());
                    LOG.fine(() -> "Reusing idle session " + candidate.id() + " for token " + tokenId);
                    return candidate;
                } else {
                    LOG.info("Evicting invalid/expired idle session " + candidate.id() + " for token " + tokenId);
                    destroySession(candidate);
                }
            }
        }

        boolean acquired = semaphore.tryAcquire(config.borrowTimeoutMs(), TimeUnit.MILLISECONDS);
        if (!acquired) {
            throw new TimeoutException("Pool capacity exhausted (maxTotal=" + config.maxTotal() +
                    "): timed out waiting for session permit (" + config.borrowTimeoutMs() + "ms)");
        }

        try {
            PooledSession session = factory.create(token, pin);
            session.touch(clock.instant());
            LOG.fine(() -> "Created new session " + session.id() + " for token " + tokenId);
            return session;
        } catch (Exception e) {
            semaphore.release();
            LOG.warning("Factory failed to create session for token " + tokenId + ": " + e.getMessage());
            throw e;
        }
    }

    /**
     * Returns a borrowed session to the pool.
     */
    public void returnSession(PooledSession session) {
        if (session == null || session.isClosed()) {
            return;
        }

        if (shutdown || !isValidAndNotExpired(session)) {
            destroySession(session);
            return;
        }

        String tokenId = session.token().id();
        ConcurrentLinkedQueue<PooledSession> queue = idleQueues.computeIfAbsent(tokenId, k -> new ConcurrentLinkedQueue<>());

        if (queue.contains(session)) {
            return;
        }

        if (queue.size() >= config.maxIdle()) {
            LOG.fine(() -> "Idle queue full for token " + tokenId + "; destroying excess session " + session.id());
            destroySession(session);
        } else {
            session.touch(clock.instant());
            queue.offer(session);
            LOG.fine(() -> "Returned session " + session.id() + " to pool for token " + tokenId);
        }
    }

    /**
     * Scans all idle queues and evicts sessions that are expired or invalid.
     */
    public void evictIdleSessions() {
        Instant now = clock.instant();
        int evictedCount = 0;

        for (Map.Entry<String, ConcurrentLinkedQueue<PooledSession>> entry : idleQueues.entrySet()) {
            ConcurrentLinkedQueue<PooledSession> queue = entry.getValue();
            for (PooledSession session : queue) {
                if (!isValidAndNotExpired(session, now)) {
                    if (queue.remove(session)) {
                        destroySession(session);
                        evictedCount++;
                    }
                }
            }
        }

        if (evictedCount > 0) {
            LOG.info("Evicted " + evictedCount + " idle/expired session(s) from pool");
        }
    }

    /**
     * Shuts down the session pool, closing all idle sessions and stopping background eviction.
     */
    public synchronized void shutdown() {
        if (shutdown) {
            return;
        }
        shutdown = true;

        if (evictionExecutor != null) {
            evictionExecutor.shutdown();
        }

        for (ConcurrentLinkedQueue<PooledSession> queue : idleQueues.values()) {
            PooledSession session;
            while ((session = queue.poll()) != null) {
                destroySession(session);
            }
        }
        idleQueues.clear();
        LOG.info("Pkcs11SessionPool shut down");
    }

    public int getIdleSessionCount(String tokenId) {
        ConcurrentLinkedQueue<PooledSession> queue = idleQueues.get(tokenId);
        return queue != null ? queue.size() : 0;
    }

    public int getActiveSessionCount() {
        return config.maxTotal() - semaphore.availablePermits();
    }

    public boolean isShutdown() {
        return shutdown;
    }

    private boolean isValidAndNotExpired(PooledSession session) {
        return isValidAndNotExpired(session, clock.instant());
    }

    private boolean isValidAndNotExpired(PooledSession session, Instant now) {
        if (!session.isValid()) {
            return false;
        }
        if (session.lastUsed().plusSeconds(config.idleTimeoutSeconds()).isBefore(now)) {
            return false;
        }
        if (session.createdAt().plusSeconds(config.maxLifetimeSeconds()).isBefore(now)) {
            return false;
        }
        return true;
    }

    private void destroySession(PooledSession session) {
        if (session == null) return;
        boolean wasClosedBefore;
        synchronized (session) {
            wasClosedBefore = session.isClosed();
            session.close();
        }
        if (!wasClosedBefore) {
            semaphore.release();
            if (auditLogger != null) {
                auditLogger.logSessionClosed(session.id(), session.token().id());
            }
        }
    }
}
