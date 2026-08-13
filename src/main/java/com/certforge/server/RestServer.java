package com.certforge.server;

import com.certforge.audit.AuditLogger;
import com.certforge.auth.Authenticator;
import com.certforge.discovery.TokenDiscoverer;
import com.certforge.discovery.TokenInfo;
import com.certforge.session.CertificateInfo;
import com.certforge.session.SessionManager;
import com.certforge.signing.PdfSigningService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RestServer {

    private static final Logger LOG = Logger.getLogger(RestServer.class.getName());
    private final TokenDiscoverer discoverer;
    private final Authenticator authenticator;
    private final SessionManager sessionManager;
    private final PdfSigningService pdfSigningService;
    private final AuditLogger auditLogger;

    public RestServer(TokenDiscoverer discoverer, Authenticator authenticator,
                      SessionManager sessionManager, PdfSigningService pdfSigningService,
                      AuditLogger auditLogger) {
        this.discoverer = discoverer;
        this.authenticator = authenticator;
        this.sessionManager = sessionManager;
        this.pdfSigningService = pdfSigningService;
        this.auditLogger = auditLogger;
    }

    public int start(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/health", this::handleHealth);
        server.createContext("/v1/tokens", withAuth(this::handleTokens));
        server.createContext("/v1/sessions", withAuth(this::handleSessions));
        server.createContext("/v1/sessions/", withAuth(this::handleSessionById));
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

                // Audit: auth failed
                auditLogger.logAuthFailed(path, remoteAddress);

                sendJson(exchange, 401, "{\"error\":\"unauthorized\",\"message\":\"Invalid or missing API key\"}");
                return;
            }

            // Audit: auth success (at FINE level - avoid log flooding)
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
            exchange.sendResponseHeaders(405, -1);
            return;
        }
        LOG.fine("Processing GET /v1/tokens request");
        List<TokenInfo> tokens = discoverer.discover();
        StringBuilder json = new StringBuilder("{\"tokens\":[");
        for (int i = 0; i < tokens.size(); i++) {
            TokenInfo t = tokens.get(i);
            if (i > 0) json.append(",");
            json.append("{")
                    .append("\"id\":\"").append(escape(t.id())).append("\",")
                    .append("\"label\":\"").append(escape(t.label())).append("\",")
                    .append("\"manufacturer\":\"").append(escape(t.manufacturer())).append("\",")
                    .append("\"serial\":\"").append(escape(t.serial())).append("\",")
                    .append("\"libraryPath\":\"").append(escape(t.libraryPath())).append("\",")
                    .append("\"slotId\":").append(t.slotId())
                    .append("}");
        }
        json.append("]}");
        sendJson(exchange, 200, json.toString());
    }

    private void handleSessions(HttpExchange exchange) throws IOException {
        if ("POST".equals(exchange.getRequestMethod())) {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String tokenId = extractJsonValue(body, "tokenId");
            String pin = extractJsonValue(body, "pin");

            LOG.fine(() -> "Processing POST /v1/sessions for tokenId=" + tokenId);

            if (tokenId == null || pin == null) {
                LOG.warning("Invalid session creation payload: missing tokenId or pin");
                auditLogger.logError("session_create", "Missing tokenId or pin");
                sendJson(exchange, 400, "{\"error\":\"bad_request\",\"message\":\"tokenId and pin are required\"}");
                return;
            }

            TokenInfo token = findToken(tokenId);
            if (token == null) {
                LOG.warning("Token not found during session creation: " + tokenId);
                auditLogger.logError("session_create", "Token not found: " + tokenId);
                sendJson(exchange, 404, "{\"error\":\"token_not_found\",\"message\":\"Token not found: " + escape(tokenId) + "\"}");
                return;
            }

            try {
                String sessionId = sessionManager.openSession(token, pin);
                LOG.info("Session successfully opened: " + sessionId + " for token " + token.id());
                sendJson(exchange, 200, "{\"sessionId\":\"" + sessionId + "\"}");
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Failed to open session for token " + tokenId + ": " + e.getMessage(), e);
                auditLogger.logError("session_create", "Failed to open session: " + e.getMessage());
                sendJson(exchange, 401, "{\"error\":\"session_open_failed\",\"message\":\"" + escape(e.getMessage()) + "\"}");
            }
        } else {
            exchange.sendResponseHeaders(405, -1);
        }
    }

    private void handleSessionById(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String[] parts = path.split("/");

        // Path formats:
        // /v1/sessions/{sessionId}
        // /v1/sessions/{sessionId}/certificates
        // /v1/sessions/{sessionId}/jobs

        if (parts.length < 4) {
            LOG.warning("Invalid session path format: " + path);
            auditLogger.logError("session_operation", "Invalid path: " + path);
            sendJson(exchange, 400, "{\"error\":\"bad_request\",\"message\":\"Invalid session path\"}");
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
            exchange.sendResponseHeaders(405, -1);
        }
    }

    private void handleListCertificates(HttpExchange exchange, String sessionId) throws IOException {
        LOG.fine(() -> "Listing certificates for session ID " + sessionId);
        try {
            List<CertificateInfo> certs = sessionManager.listCertificates(sessionId);
            StringBuilder json = new StringBuilder("{\"certificates\":[");
            for (int i = 0; i < certs.size(); i++) {
                CertificateInfo c = certs.get(i);
                if (i > 0) json.append(",");
                json.append("{")
                        .append("\"alias\":\"").append(escape(c.alias())).append("\",")
                        .append("\"subject\":\"").append(escape(c.subject())).append("\",")
                        .append("\"issuer\":\"").append(escape(c.issuer())).append("\",")
                        .append("\"serialNumber\":\"").append(escape(c.serialNumber())).append("\",")
                        .append("\"notBefore\":\"").append(escape(c.notBefore())).append("\",")
                        .append("\"notAfter\":\"").append(escape(c.notAfter())).append("\",")
                        .append("\"keyType\":\"").append(escape(c.keyType())).append("\",")
                        .append("\"keySize\":").append(c.keySize())
                        .append("}");
            }
            json.append("]}");
            sendJson(exchange, 200, json.toString());
        } catch (Exception e) {
            LOG.warning("Failed to list certificates for session " + sessionId + ": " + e.getMessage());
            sendJson(exchange, 404, "{\"error\":\"session_not_found\",\"message\":\"" + escape(e.getMessage()) + "\"}");
        }
    }

    private void handleSignJob(HttpExchange exchange, String sessionId) throws IOException {
        LOG.fine(() -> "Processing sign job for session ID " + sessionId);
        try {
            // Read JSON body
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String documentBase64 = extractJsonValue(body, "document");
            String alias = extractJsonValue(body, "alias");

            if (documentBase64 == null || alias == null) {
                auditLogger.logError("sign_job", "Missing document or alias");
                sendJson(exchange, 400, "{\"error\":\"bad_request\",\"message\":\"document (base64) and alias are required\"}");
                return;
            }

            // Decode base64 PDF
            byte[] pdfBytes = Base64.getDecoder().decode(documentBase64);
            LOG.info("Signing PDF (" + pdfBytes.length + " bytes) with alias '" + alias + "'");

            // Sign PDF
            byte[] signedPdf = pdfSigningService.signPdf(sessionId, alias, pdfBytes);

            // Encode signed PDF as base64
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
            sendJson(exchange, 400, "{\"error\":\"bad_request\",\"message\":\"Invalid base64 document data\"}");
        } catch (Exception e) {
            LOG.log(Level.WARNING, "PDF signing failed: " + e.getMessage(), e);
            auditLogger.logError("sign_job", "Signing failed: " + e.getMessage());
            sendJson(exchange, 500, "{\"error\":\"signing_failed\",\"message\":\"" + escape(e.getMessage()) + "\"}");
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

    private String extractJsonValue(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return null;

        int colonIndex = json.indexOf(":", keyIndex + searchKey.length());
        if (colonIndex < 0) return null;

        int valueStart = colonIndex + 1;
        while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
            valueStart++;
        }

        if (valueStart < json.length() && json.charAt(valueStart) == '"') {
            StringBuilder value = new StringBuilder();
            for (int i = valueStart + 1; i < json.length(); i++) {
                char c = json.charAt(i);
                if (c == '\\' && i + 1 < json.length()) {
                    value.append(json.charAt(i + 1));
                    i++;
                } else if (c == '"') {
                    return value.toString();
                } else {
                    value.append(c);
                }
            }
        }

        return null;
    }

    private String escape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
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