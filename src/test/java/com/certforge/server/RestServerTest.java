package com.certforge.server;

import com.certforge.auth.Authenticator;
import com.certforge.discovery.TokenDiscoverer;
import com.certforge.discovery.TokenInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RestServerTest {

    private RestServer server;
    private int port;
    private HttpClient client;

    @BeforeEach
    void setUp() throws IOException {
        // Use a static token list: one valid key "good-key"
        Authenticator auth = apiKey -> apiKey.equals("good-key");
        // TokenDiscoverer that returns a fixed list
        TokenDiscoverer discoverer = () -> List.of(
                new TokenInfo("slot-1", "TestToken", "TestManuf", "1234",
                        "/lib/test.so", 1L)
        );
        server = new RestServer(discoverer, auth);
        port = server.start(0); // 0 = random port
        client = HttpClient.newHttpClient();
    }

    @AfterEach
    void tearDown() {
        // Stop the server? Not necessary if we just let JVM exit, but to be safe we can.
        // HttpServer doesn't have a stop method easily accessible. We'll ignore.
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
        // Optionally check body contains token
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
    void tokensEndpointReturns401WithWrongAuthScheme() throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/v1/tokens"))
                .header("Authorization", "Basic good-key")
                .GET()
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, response.statusCode());
    }
}