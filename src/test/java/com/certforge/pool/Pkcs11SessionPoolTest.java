package com.certforge.pool;

import com.certforge.discovery.TokenInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

public class Pkcs11SessionPoolTest {

    private MutableClock clock;
    private TokenInfo testToken;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-08-14T10:00:00Z"));
        testToken = new TokenInfo("token1", "Test Token", "CertForge", "12345", "/lib/pkcs11.so", 0L);
    }

    @Test
    void borrowCreatesNewSessionWhenPoolEmpty() throws Exception {
        FakeSessionFactory factory = new FakeSessionFactory(clock);
        PoolConfig config = PoolConfig.defaultConfig();
        Pkcs11SessionPool pool = new Pkcs11SessionPool(config, factory, null, clock);

        PooledSession session = pool.borrow(testToken, "1234");
        assertNotNull(session);
        assertEquals("token1", session.token().id());
        assertEquals(1, factory.getCreateCount());
        assertEquals(1, pool.getActiveSessionCount());
    }

    @Test
    void returnSessionAllowsReuse() throws Exception {
        FakeSessionFactory factory = new FakeSessionFactory(clock);
        PoolConfig config = PoolConfig.defaultConfig();
        Pkcs11SessionPool pool = new Pkcs11SessionPool(config, factory, null, clock);

        PooledSession session1 = pool.borrow(testToken, "1234");
        assertEquals(1, factory.getCreateCount());

        pool.returnSession(session1);
        assertEquals(1, pool.getIdleSessionCount(testToken.id()));

        PooledSession session2 = pool.borrow(testToken, "1234");
        assertSame(session1, session2);
        assertEquals(1, factory.getCreateCount());
    }

    @Test
    void borrowBlocksWhenExhaustedAndTimesOut() throws Exception {
        FakeSessionFactory factory = new FakeSessionFactory(clock);
        PoolConfig config = new PoolConfig(2, 2, 600, 3600, 30, 100L); // maxTotal = 2, timeout = 100ms
        Pkcs11SessionPool pool = new Pkcs11SessionPool(config, factory, null, clock);

        PooledSession s1 = pool.borrow(testToken, "1234");
        PooledSession s2 = pool.borrow(testToken, "1234");
        assertEquals(2, factory.getCreateCount());

        long start = System.currentTimeMillis();
        Exception exception = assertThrows(TimeoutException.class, () -> {
            pool.borrow(testToken, "1234");
        });
        long duration = System.currentTimeMillis() - start;

        assertTrue(duration >= 90, "Should wait approximately borrowTimeoutMs");
        assertTrue(exception.getMessage().contains("exhausted") || exception.getMessage().contains("timed out"));
    }

    @Test
    void invalidSessionIsClosedAndNewOneCreated() throws Exception {
        FakeSessionFactory factory = new FakeSessionFactory(clock);
        PoolConfig config = PoolConfig.defaultConfig();
        Pkcs11SessionPool pool = new Pkcs11SessionPool(config, factory, null, clock);

        PooledSession session1 = pool.borrow(testToken, "1234");
        pool.returnSession(session1);

        session1.setValid(false); // Simulate session failure

        PooledSession session2 = pool.borrow(testToken, "1234");
        assertNotSame(session1, session2);
        assertTrue(session1.isClosed());
        assertEquals(2, factory.getCreateCount());
    }

    @Test
    void evictIdleSessionAfterTimeout() throws Exception {
        FakeSessionFactory factory = new FakeSessionFactory(clock);
        PoolConfig config = new PoolConfig(10, 5, 600, 3600, 30, 2000L); // 600s idle timeout
        Pkcs11SessionPool pool = new Pkcs11SessionPool(config, factory, null, clock);

        PooledSession session = pool.borrow(testToken, "1234");
        pool.returnSession(session);
        assertEquals(1, pool.getIdleSessionCount(testToken.id()));

        // Advance clock by 601 seconds
        clock.advanceSeconds(601);

        pool.evictIdleSessions();

        assertEquals(0, pool.getIdleSessionCount(testToken.id()));
        assertTrue(session.isClosed());

        // Permit should be available for new session creation
        PooledSession session2 = pool.borrow(testToken, "1234");
        assertNotSame(session, session2);
    }

    @Test
    void shutdownClosesIdleSessions() throws Exception {
        FakeSessionFactory factory = new FakeSessionFactory(clock);
        PoolConfig config = PoolConfig.defaultConfig();
        Pkcs11SessionPool pool = new Pkcs11SessionPool(config, factory, null, clock);

        PooledSession s1 = pool.borrow(testToken, "1234");
        pool.returnSession(s1);

        assertEquals(1, pool.getIdleSessionCount(testToken.id()));
        assertFalse(s1.isClosed());

        pool.shutdown();

        assertEquals(0, pool.getIdleSessionCount(testToken.id()));
        assertTrue(s1.isClosed());
        assertTrue(pool.isShutdown());

        assertThrows(IllegalStateException.class, () -> pool.borrow(testToken, "1234"));
    }

    @Test
    void factoryFailureReleasesCreationPermit() {
        AtomicInteger attempts = new AtomicInteger(0);
        Pkcs11SessionFactory failingFactory = (token, pin) -> {
            if (attempts.incrementAndGet() == 1) {
                throw new RuntimeException("PKCS11 init error");
            }
            return new PooledSession(token, null, null, pin != null ? pin.toCharArray() : null, clock.instant());
        };

        PoolConfig config = new PoolConfig(1, 1, 600, 3600, 30, 500L); // maxTotal = 1
        Pkcs11SessionPool pool = new Pkcs11SessionPool(config, failingFactory, null, clock);

        // Attempt 1 fails
        assertThrows(RuntimeException.class, () -> pool.borrow(testToken, "1234"));

        // Attempt 2 must succeed because permit was released on failure
        assertDoesNotThrow(() -> {
            PooledSession s = pool.borrow(testToken, "1234");
            assertNotNull(s);
        });
    }

    @Test
    void sessionExceedingMaxLifetimeIsClosedOnBorrow() throws Exception {
        FakeSessionFactory factory = new FakeSessionFactory(clock);
        PoolConfig config = new PoolConfig(10, 5, 600, 3600, 30, 2000L); // 3600s max lifetime
        Pkcs11SessionPool pool = new Pkcs11SessionPool(config, factory, null, clock);

        PooledSession session1 = pool.borrow(testToken, "1234");
        pool.returnSession(session1);

        // Advance clock past maxLifetime (3601 seconds)
        clock.advanceSeconds(3601);

        PooledSession session2 = pool.borrow(testToken, "1234");
        assertNotSame(session1, session2);
        assertTrue(session1.isClosed());
        assertEquals(2, factory.getCreateCount());
    }

    @Test
    void returningSameSessionTwiceDoesNotDuplicateIt() throws Exception {
        FakeSessionFactory factory = new FakeSessionFactory(clock);
        PoolConfig config = PoolConfig.defaultConfig();
        Pkcs11SessionPool pool = new Pkcs11SessionPool(config, factory, null, clock);

        PooledSession session = pool.borrow(testToken, "1234");
        pool.returnSession(session);
        pool.returnSession(session); // Second call should be ignored / harmless

        assertEquals(1, pool.getIdleSessionCount(testToken.id()));
    }

    @Test
    @Timeout(5)
    void concurrentBorrowsDoNotExceedMaxTotal() throws Exception {
        int maxTotal = 5;
        FakeSessionFactory factory = new FakeSessionFactory(clock);
        PoolConfig config = new PoolConfig(maxTotal, 5, 600, 3600, 30, 1000L);
        Pkcs11SessionPool pool = new Pkcs11SessionPool(config, factory, null, clock);

        int threads = 15;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch latch = new CountDownLatch(1);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    latch.await();
                    PooledSession s = pool.borrow(testToken, "1234");
                    if (s != null) {
                        successCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    failureCount.incrementAndGet();
                }
            });
        }

        latch.countDown();
        executor.shutdown();
        assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS));

        assertEquals(maxTotal, successCount.get(), "Successful borrows should equal maxTotal");
        assertEquals(threads - maxTotal, failureCount.get(), "Excess requests should fail with timeout");
        assertTrue(factory.getCreateCount() <= maxTotal, "Factory calls must not exceed maxTotal");
    }

    // Helper fake factory
    static class FakeSessionFactory implements Pkcs11SessionFactory {
        private final AtomicInteger createCount = new AtomicInteger(0);
        private final Clock clock;

        FakeSessionFactory(Clock clock) {
            this.clock = clock;
        }

        @Override
        public PooledSession create(TokenInfo token, String pin) {
            createCount.incrementAndGet();
            return new PooledSession(token, null, null, pin != null ? pin.toCharArray() : null, clock.instant());
        }

        int getCreateCount() {
            return createCount.get();
        }
    }

    // Helper mutable clock for deterministic time manipulation
    static class MutableClock extends Clock {
        private Instant currentInstant;

        MutableClock(Instant start) {
            this.currentInstant = start;
        }

        void advanceSeconds(long seconds) {
            this.currentInstant = this.currentInstant.plusSeconds(seconds);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return currentInstant;
        }
    }
}
