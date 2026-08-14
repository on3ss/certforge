package com.certforge.audit;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AuditLogger {

    private static final Logger LOG = Logger.getLogger(AuditLogger.class.getName());

    private final Path baseAuditPath;
    private final ReentrantLock lock = new ReentrantLock();
    private String currentDate;

    public AuditLogger(Path auditPath) {
        this.baseAuditPath = auditPath;
        this.currentDate = LocalDate.now().format(DateTimeFormatter.ISO_DATE);
        LOG.info("Audit logger initialized. Writing to: " + auditPath);
    }

    public void log(AuditEvent event) {
        lock.lock();
        try {
            String today = LocalDate.now().format(DateTimeFormatter.ISO_DATE);
            if (!today.equals(currentDate)) {
                currentDate = today;
                LOG.info("Audit log rotated to date: " + currentDate);
            }

            Path resolvedPath = getResolvedPath();
            String jsonLine = event.toJson() + System.lineSeparator();

            Path parent = resolvedPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            Files.writeString(
                    resolvedPath,
                    jsonLine,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND,
                    StandardOpenOption.WRITE
            );

        } catch (IOException e) {
            LOG.log(Level.WARNING, "Failed to write audit event: " + e.getMessage(), e);
        } finally {
            lock.unlock();
        }
    }

    // Generic event
    public void logEvent(AuditEventType type, Map<String, String> fields) {
        log(new AuditEvent(type, fields));
    }

    // Lifecycle
    public void logStarted(String version) {
        logEvent(AuditEventType.GATEWAY_STARTED, Map.of("version", version));
    }

    public void logStopped() {
        logEvent(AuditEventType.GATEWAY_STOPPED, Map.of());
    }

    // Config
    public void logConfigLoaded(String path) {
        logEvent(AuditEventType.CONFIG_LOADED, Map.of("path", path));
    }

    public void logConfigNotFound(String path) {
        logEvent(AuditEventType.CONFIG_NOT_FOUND, Map.of("path", path));
    }

    public void logConfigParseError(String path, String error) {
        logEvent(AuditEventType.CONFIG_PARSE_ERROR, Map.of("path", path, "error", error));
    }

    // Discovery
    public void logDiscoveryStarted(int libraryCount) {
        logEvent(AuditEventType.TOKEN_DISCOVERY_STARTED, Map.of("libraries", String.valueOf(libraryCount)));
    }

    public void logDiscoveryCompleted(int tokenCount) {
        logEvent(AuditEventType.TOKEN_DISCOVERY_COMPLETED, Map.of("tokensFound", String.valueOf(tokenCount)));
    }

    public void logLibraryProbed(String libraryPath, String result) {
        logEvent(AuditEventType.LIBRARY_PROBED, Map.of("library", libraryPath, "result", result));
    }

    public void logTokenFound(String tokenId, String label, String serial) {
        logEvent(AuditEventType.TOKEN_FOUND, Map.of(
                "tokenId", tokenId,
                "label", label,
                "serial", serial
        ));
    }

    // Auth
    public void logAuthSuccess(String path, String remoteAddress) {
        logEvent(AuditEventType.AUTH_SUCCESS, Map.of(
                "path", path,
                "remoteAddress", remoteAddress
        ));
    }

    public void logAuthFailed(String path, String remoteAddress) {
        logEvent(AuditEventType.AUTH_FAILED, Map.of(
                "path", path,
                "remoteAddress", remoteAddress
        ));
    }

    // Session
    public void logSessionOpened(String sessionId, String tokenId) {
        logEvent(AuditEventType.SESSION_OPENED, Map.of(
                "sessionId", sessionId,
                "tokenId", tokenId
        ));
    }

    public void logSessionClosed(String sessionId, String tokenId) {
        logEvent(AuditEventType.SESSION_CLOSED, Map.of(
                "sessionId", sessionId,
                "tokenId", tokenId
        ));
    }

    public void logSessionExpired(String sessionId) {
        logEvent(AuditEventType.SESSION_EXPIRED, Map.of("sessionId", sessionId));
    }

    public void logSessionNotFound(String sessionId) {
        logEvent(AuditEventType.SESSION_NOT_FOUND, Map.of("sessionId", sessionId));
    }

    // Pool
    public void logPoolBorrow(String sessionId, String tokenId) {
        logEvent(AuditEventType.POOL_BORROW, Map.of("sessionId", sessionId, "tokenId", tokenId));
    }

    public void logPoolReturn(String sessionId, String tokenId) {
        logEvent(AuditEventType.POOL_RETURN, Map.of("sessionId", sessionId, "tokenId", tokenId));
    }

    public void logPoolExhausted(String tokenId) {
        logEvent(AuditEventType.POOL_EXHAUSTED, Map.of("tokenId", tokenId));
    }

    public void logPoolEvict(String sessionId, String tokenId) {
        logEvent(AuditEventType.POOL_EVICT, Map.of("sessionId", sessionId, "tokenId", tokenId));
    }

    // Signing
    public void logDocumentSigned(String sessionId, String alias, String result,
                                  long pdfSize, long signatureSize) {
        logEvent(AuditEventType.DOCUMENT_SIGNED, Map.of(
                "sessionId", sessionId,
                "alias", alias,
                "result", result,
                "pdfSize", String.valueOf(pdfSize),
                "signatureSize", String.valueOf(signatureSize)
        ));
    }

    public void logSigningFailed(String sessionId, String alias, String error) {
        logEvent(AuditEventType.SIGNING_FAILED, Map.of(
                "sessionId", sessionId,
                "alias", alias,
                "error", error
        ));
    }

    // Verification
    public void logDocumentVerified(String result, int signatureCount) {
        logEvent(AuditEventType.DOCUMENT_VERIFIED, Map.of(
                "result", result,
                "signatureCount", String.valueOf(signatureCount)
        ));
    }

    // Errors
    public void logError(String operation, String message) {
        logEvent(AuditEventType.ERROR, Map.of(
                "operation", operation,
                "message", message
        ));
    }

    // API Requests
    public void logRequestReceived(String method, String path) {
        logEvent(AuditEventType.REQUEST_RECEIVED, Map.of(
                "method", method,
                "path", path
        ));
    }

    public void logRequestCompleted(String method, String path, int statusCode, long durationMs) {
        logEvent(AuditEventType.REQUEST_COMPLETED, Map.of(
                "method", method,
                "path", path,
                "statusCode", String.valueOf(statusCode),
                "durationMs", String.valueOf(durationMs)
        ));
    }

    /**
     * Convenience method for logging verification events.
     */
    public void logVerifyEvent(String result, int signatureCount) {
        logEvent(AuditEventType.DOCUMENT_VERIFIED, Map.of(
                "result", result,
                "signatureCount", String.valueOf(signatureCount)
        ));
    }

    /**
     * Convenience method for logging verification failures.
     */
    public void logVerificationFailed(String error) {
        logEvent(AuditEventType.VERIFICATION_FAILED, Map.of(
                "error", error
        ));
    }

    private Path getResolvedPath() {
        String fileName = baseAuditPath.getFileName().toString();
        String baseName = fileName;
        String extension = "";

        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex > 0) {
            baseName = fileName.substring(0, dotIndex);
            extension = fileName.substring(dotIndex);
        }

        String rotatedName = baseName + "-" + currentDate + extension;
        Path parent = baseAuditPath.getParent();
        return parent != null ? parent.resolve(rotatedName) : Path.of(rotatedName);
    }
}