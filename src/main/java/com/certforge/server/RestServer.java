package com.certforge.server;

import com.certforge.audit.AuditLogger;
import com.certforge.auth.Authenticator;
import com.certforge.discovery.TokenDiscoverer;
import com.certforge.discovery.TokenInfo;
import com.certforge.session.CertificateInfo;
import com.certforge.session.SessionManager;
import com.certforge.signing.SigningService;
import com.certforge.verify.VerificationService;
import com.certforge.verify.VerificationResult;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RestServer {

    private static final Logger LOG = Logger.getLogger(RestServer.class.getName());
    private final TokenDiscoverer discoverer;
    private final Authenticator authenticator;
    private final SessionManager sessionManager;
    private final SigningService signingService;
    private final AuditLogger auditLogger;
    private final VerificationService verificationService;

    public RestServer(TokenDiscoverer discoverer, Authenticator authenticator,
                      SessionManager sessionManager, SigningService signingService,
                      AuditLogger auditLogger, VerificationService verificationService) {
        this.discoverer = Objects.requireNonNull(discoverer, "discoverer cannot be null");
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator cannot be null");
        this.sessionManager = Objects.requireNonNull(sessionManager, "sessionManager cannot be null");
        this.signingService = Objects.requireNonNull(signingService, "signingService cannot be null");
        this.auditLogger = Objects.requireNonNull(auditLogger, "auditLogger cannot be null");
        this.verificationService = Objects.requireNonNull(verificationService, "verificationService cannot be null");
    }

    public int start(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/health", this::handleHealth);
        server.createContext("/v1/tokens", withAuth(this::handleTokens));
        server.createContext("/v1/sessions", withAuth(this::handleSessions));
        server.createContext("/v1/sessions/", withAuth(this::handleSessionById));
        server.createContext("/v1/verify", withAuth(this::handleVerify));
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(4));
        server.start();
        int actualPort = server.getAddress().getPort();
        LOG.info("Gateway REST API listening on http://127.0.0.1:" + actualPort);
        return actualPort;
    }

    private HttpHandler withAuth(HttpHandler handler) {
        return exchange -> {
            String path = exchange.getRequestURI().getPath();
            String remoteAddress = exchange.getRemoteAddress().getAddress().getHostAddress();

            if (!isAuthenticated(exchange)) {
                LOG.warning("Unauthorized access attempt to " + path);
                auditLogger.logAuthFailed(path, remoteAddress);
                sendError(exchange, 401, "unauthorized", "Invalid or missing API key");
                return;
            }

            auditLogger.logAuthSuccess(path, remoteAddress);
            handler.handle(exchange);
        };
    }

    private boolean isAuthenticated(HttpExchange exchange) {
        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return false;
        }
        String token = authHeader.substring(7).trim();
        return authenticator.isValid(token);
    }

    private void handleHealth(HttpExchange exchange) throws IOException {
        sendJson(exchange, 200, "{\"status\":\"UP\"}");
    }

    private void handleTokens(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendError(exchange, 405, "method_not_allowed", "Method " + exchange.getRequestMethod() + " not allowed for /v1/tokens");
            return;
        }
        LOG.fine("Processing GET /v1/tokens request");
        List<TokenInfo> tokens = discoverer.discover();
        sendJson(exchange, 200, JsonUtils.buildTokensJson(tokens));
    }

    private void handleSessions(HttpExchange exchange) throws IOException {
        if ("POST".equals(exchange.getRequestMethod())) {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String tokenId = JsonUtils.extractJsonValue(body, "tokenId");
            String pin = JsonUtils.extractJsonValue(body, "pin");

            LOG.fine(() -> "Processing POST /v1/sessions for tokenId=" + tokenId);

            if (tokenId == null || pin == null) {
                LOG.warning("Invalid session creation payload: missing tokenId or pin");
                auditLogger.logError("session_create", "Missing tokenId or pin");
                sendError(exchange, 400, "bad_request", "tokenId and pin are required");
                return;
            }

            TokenInfo token = findToken(tokenId);
            if (token == null) {
                LOG.warning("Token not found during session creation: " + tokenId);
                auditLogger.logError("session_create", "Token not found: " + tokenId);
                sendError(exchange, 404, "token_not_found", "Token not found: " + tokenId);
                return;
            }

            try {
                String sessionId = sessionManager.openSession(token, pin);
                LOG.info("Session successfully opened: " + sessionId + " for token " + token.id());
                sendJson(exchange, 200, "{\"sessionId\":\"" + sessionId + "\"}");
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Failed to open session for token " + tokenId + ": " + e.getMessage(), e);
                auditLogger.logError("session_create", "Failed to open session: " + e.getMessage());
                sendError(exchange, 401, "session_open_failed", e.getMessage());
            }
        } else {
            sendError(exchange, 405, "method_not_allowed", "Method " + exchange.getRequestMethod() + " not allowed for /v1/sessions");
        }
    }

    private void handleSessionById(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String[] parts = path.split("/");

        if (parts.length < 4) {
            LOG.warning("Invalid session path format: " + path);
            auditLogger.logError("session_operation", "Invalid path: " + path);
            sendError(exchange, 400, "bad_request", "Invalid session path");
            return;
        }

        String sessionId = parts[3];
        boolean listCerts = parts.length >= 5 && "certificates".equals(parts[4]);
        boolean signJob = parts.length >= 5 && "jobs".equals(parts[4]);

        if ("GET".equals(exchange.getRequestMethod()) && listCerts) {
            handleListCertificates(exchange, sessionId);
        } else if ("POST".equals(exchange.getRequestMethod()) && signJob) {
            handleSignJob(exchange, sessionId);
        } else if ("DELETE".equals(exchange.getRequestMethod())) {
            LOG.fine(() -> "Closing session ID " + sessionId);
            sessionManager.closeSession(sessionId);
            sendJson(exchange, 200, "{\"status\":\"closed\"}");
        } else {
            sendError(exchange, 405, "method_not_allowed", "Method " + exchange.getRequestMethod() + " not allowed for " + path);
        }
    }

    private void handleListCertificates(HttpExchange exchange, String sessionId) throws IOException {
        LOG.fine(() -> "Listing certificates for session ID " + sessionId);
        try {
            List<CertificateInfo> certs = sessionManager.listCertificates(sessionId);
            sendJson(exchange, 200, JsonUtils.buildCertificatesJson(certs));
        } catch (Exception e) {
            LOG.warning("Failed to list certificates for session " + sessionId + ": " + e.getMessage());
            sendError(exchange, 404, "session_not_found", e.getMessage());
        }
    }

    private void handleSignJob(HttpExchange exchange, String sessionId) throws IOException {
        LOG.fine(() -> "Processing sign job for session ID " + sessionId);
        try {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String documentBase64 = JsonUtils.extractJsonValue(body, "document");
            String alias = JsonUtils.extractJsonValue(body, "alias");

            if (documentBase64 == null || alias == null) {
                auditLogger.logError("sign_job", "Missing document or alias");
                sendError(exchange, 400, "bad_request", "document (base64) and alias are required");
                return;
            }

            byte[] pdfBytes = Base64.getDecoder().decode(documentBase64);
            LOG.info("Signing PDF (" + pdfBytes.length + " bytes) with alias '" + alias + "'");

            byte[] signedPdf = signingService.signPdf(sessionId, alias, pdfBytes);
            String signedBase64 = Base64.getEncoder().encodeToString(signedPdf);
            String jobId = "job_" + UUID.randomUUID().toString().replace("-", "");

            String response = "{"
                    + "\"jobId\":\"" + jobId + "\","
                    + "\"status\":\"completed\","
                    + "\"document\":{"
                    + "\"data\":\"" + signedBase64 + "\","
                    + "\"filename\":\"signed-document.pdf\""
                    + "}"
                    + "}";
            sendJson(exchange, 200, response);

        } catch (IllegalArgumentException e) {
            LOG.warning("Invalid base64 document: " + e.getMessage());
            auditLogger.logError("sign_job", "Invalid base64 document");
            sendError(exchange, 400, "bad_request", "Invalid base64 document data");
        } catch (Exception e) {
            LOG.log(Level.WARNING, "PDF signing failed: " + e.getMessage(), e);
            auditLogger.logError("sign_job", "Signing failed: " + e.getMessage());
            sendError(exchange, 500, "signing_failed", e.getMessage());
        }
    }

    private void handleVerify(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendError(exchange, 405, "method_not_allowed", "Method " + exchange.getRequestMethod() + " not allowed for /v1/verify");
            return;
        }

        try {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String documentBase64 = JsonUtils.extractJsonValue(body, "document");

            if (documentBase64 == null) {
                sendError(exchange, 400, "bad_request", "document (base64) is required");
                return;
            }

            byte[] pdfBytes = Base64.getDecoder().decode(documentBase64);
            LOG.info("Verifying PDF (" + pdfBytes.length + " bytes)");

            VerificationResult result = verificationService.verify(pdfBytes);
            sendJson(exchange, 200, result.toJson());

        } catch (IllegalArgumentException e) {
            sendError(exchange, 400, "bad_request", "Invalid base64 document data");
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Verification failed: " + e.getMessage(), e);
            sendError(exchange, 500, "verification_failed", e.getMessage());
        }
    }

    private TokenInfo findToken(String tokenId) {
        List<TokenInfo> tokens = discoverer.discover();
        for (TokenInfo token : tokens) {
            if (token.id().equals(tokenId)) {
                return token;
            }
        }
        return null;
    }

    private void sendError(HttpExchange exchange, int statusCode, String errorCode, String message) throws IOException {
        sendJson(exchange, statusCode, JsonUtils.buildErrorJson(statusCode, errorCode, message));
    }

    private void sendJson(HttpExchange exchange, int code, String body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}