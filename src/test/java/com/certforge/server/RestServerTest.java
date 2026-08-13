package com.certforge.server;

import com.certforge.auth.Authenticator;
import com.certforge.discovery.TokenDiscoverer;
import com.certforge.discovery.TokenInfo;
import com.certforge.session.SessionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RestServerTest {

    private RestServer server;
    private int port;
    private HttpClient client;

    @BeforeEach
    void setUp() throws IOException {
        Authenticator auth = apiKey -> apiKey.equals("good-key");
        TokenDiscoverer discoverer = () -> List.of(
                new TokenInfo("slot-1", "TestToken", "TestManuf", "1234",
                        "/lib/test.so", 1L)
        );
        SessionManager sessionManager = new SessionManager();
        server = new RestServer(discoverer, auth, sessionManager);
        port = server.start(0);
        client = HttpClient.newHttpClient();
    }

    @Test
    void healthEndpointReturns200WithoutAuth() throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/health"))
                .GET()
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
    }

    @Test
    void tokensEndpointReturns401WithoutAuth() throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/v1/tokens"))
                .GET()
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, response.statusCode());
    }

    @Test
    void tokensEndpointReturns200WithValidAuth() throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/v1/tokens"))
                .header("Authorization", "Bearer good-key")
                .GET()
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("TestToken"));
    }

    @Test
    void tokensEndpointReturns401WithInvalidAuth() throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/v1/tokens"))
                .header("Authorization", "Bearer bad-key")
                .GET()
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, response.statusCode());
    }

    @Test
    void sessionsEndpointReturns400WithMissingFields() throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/v1/sessions"))
                .header("Authorization", "Bearer good-key")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(400, response.statusCode());
    }

    @Test
    void sessionsEndpointReturns404ForUnknownToken() throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/v1/sessions"))
                .header("Authorization", "Bearer good-key")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"tokenId\":\"unknown\",\"pin\":\"1234\"}"))
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(404, response.statusCode());
    }

    @Test
    void sessionByIdReturns404ForUnknownSession() throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/v1/sessions/nonexistent/certificates"))
                .header("Authorization", "Bearer good-key")
                .GET()
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(404, response.statusCode());
    }

    @Test
    void sessionDeleteReturns200() throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/v1/sessions/some-session-id"))
                .header("Authorization", "Bearer good-key")
                .DELETE()
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
    }
}