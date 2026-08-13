package com.certforge.session;

import com.certforge.audit.AuditLogger;
import com.certforge.discovery.TokenInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class SessionManagerTest {

    @TempDir
    Path tempDir;

    private AuditLogger auditLogger;
    private SessionManager sessionManager;

    @BeforeEach
    void setUp() {
        auditLogger = new AuditLogger(tempDir.resolve("audit.log"));
        sessionManager = new SessionManager(auditLogger, 1, 2);
    }

    @AfterEach
    void tearDown() {
        sessionManager.shutdown();
    }

    @Test
    void sessionShouldNotExistInitially() {
        assertFalse(sessionManager.sessionExists("nonexistent"));
    }

    @Test
    void sessionShouldExpireAfterInactivity() throws Exception {
        // Skip if SoftHSM2 not available
        assumeTrue(tokenAvailable(), "SoftHSM2 token not available for testing");

        TokenInfo token = new TokenInfo(
                "slot-249215396", "SoftHSMToken1", "SoftHSM project", "09af31a70edab9a4",
                "E:\\SoftHSM2\\lib\\softhsm2-x64.dll", 249215396L
        );

        String sessionId = sessionManager.openSession(token, "1234");
        assertTrue(sessionManager.sessionExists(sessionId));

        Thread.sleep(1500);
        assertFalse(sessionManager.sessionExists(sessionId));
    }

    @Test
    void sessionShouldExpireAfterMaxLifetime() throws Exception {
        assumeTrue(tokenAvailable(), "SoftHSM2 token not available for testing");

        TokenInfo token = new TokenInfo(
                "slot-249215396", "SoftHSMToken1", "SoftHSM project", "09af31a70edab9a4",
                "E:\\SoftHSM2\\lib\\softhsm2-x64.dll", 249215396L
        );

        String sessionId = sessionManager.openSession(token, "1234");
        assertTrue(sessionManager.sessionExists(sessionId));

        Thread.sleep(2500);
        assertFalse(sessionManager.sessionExists(sessionId));
    }

    @Test
    void closeSessionRemovesSession() throws Exception {
        assumeTrue(tokenAvailable(), "SoftHSM2 token not available for testing");

        TokenInfo token = new TokenInfo(
                "slot-249215396", "SoftHSMToken1", "SoftHSM project", "09af31a70edab9a4",
                "E:\\SoftHSM2\\lib\\softhsm2-x64.dll", 249215396L
        );

        String sessionId = sessionManager.openSession(token, "1234");
        assertTrue(sessionManager.sessionExists(sessionId));

        sessionManager.closeSession(sessionId);
        assertFalse(sessionManager.sessionExists(sessionId));
    }

    @Test
    void getSessionThrowsForNonexistent() {
        assertThrows(Exception.class, () -> sessionManager.getKeyStore("nonexistent"));
    }

    private boolean tokenAvailable() {
        return Files.exists(Path.of("E:\\SoftHSM2\\lib\\softhsm2-x64.dll"));
    }
}