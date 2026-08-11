package com.certforge.server;

import com.certforge.auth.Authenticator;
import com.certforge.discovery.TokenDiscoverer;
import com.certforge.discovery.TokenInfo;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.logging.Logger;

public class RestServer {

    private static final Logger LOG = Logger.getLogger(RestServer.class.getName());
    private final TokenDiscoverer discoverer;
    private final Authenticator authenticator;

    public RestServer(TokenDiscoverer discoverer, Authenticator authenticator) {
        this.discoverer = discoverer;
        this.authenticator = authenticator;
    }

    public int start(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/health", this::handleHealth);
        server.createContext("/v1/tokens", withAuth(this::handleTokens));
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(4));
        server.start();
        int actualPort = server.getAddress().getPort();
        LOG.info("Gateway REST API listening on http://127.0.0.1:" + actualPort);
        return actualPort;
    }

    private HttpHandler withAuth(HttpHandler handler) {
        return exchange -> {
            if (!isAuthenticated(exchange)) {
                sendJson(exchange, 401, "{\"error\":\"unauthorized\",\"message\":\"Invalid or missing API key\"}");
                return;
            }
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
        List<TokenInfo> tokens = discoverer.discover();
        StringBuilder json = new StringBuilder("{\"tokens\":[");
        for (int i = 0; i < tokens.size(); i++) {
            TokenInfo t = tokens.get(i);
            if (i > 0) json.append(",");
            json.append("{")
                    .append("\"id\":\"").append(t.getId()).append("\",")
                    .append("\"label\":\"").append(escape(t.getLabel())).append("\",")
                    .append("\"manufacturer\":\"").append(escape(t.getManufacturer())).append("\",")
                    .append("\"serial\":\"").append(escape(t.getSerial())).append("\",")
                    .append("\"libraryPath\":\"").append(escape(t.getLibraryPath())).append("\",")
                    .append("\"slotId\":").append(t.getSlotId())
                    .append("}");
        }
        json.append("]}");
        sendJson(exchange, 200, json.toString());
    }

    private String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
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