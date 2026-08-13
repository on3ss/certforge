package com.certforge.server;

import com.certforge.auth.Authenticator;
import com.certforge.discovery.TokenDiscoverer;
import com.certforge.discovery.TokenInfo;
import com.certforge.session.SessionManager;
import com.certforge.signing.PdfSigningService;
import com.certforge.signing.certificate.CertificateChainValidator;
import com.certforge.signing.cms.CmsSigningService;
import com.certforge.signing.crypto.SigningKeyProvider;
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
    private SessionManager sessionManager;

    @BeforeEach
    void setUp() throws IOException {
        // Use a static token list: one valid key "good-key"
        Authenticator auth = apiKey -> apiKey.equals("good-key");

        // TokenDiscoverer that returns a fixed list
        TokenDiscoverer discoverer = () -> List.of(
                new TokenInfo("slot-1", "TestToken", "TestManuf", "1234",
                        "/lib/test.so", 1L)
        );

        // Create SessionManager
        sessionManager = new SessionManager();

        // Create signing service components
        SigningKeyProvider signingKeyProvider = new SigningKeyProvider(sessionManager);
        CertificateChainValidator certValidator = new CertificateChainValidator();
        CmsSigningService cmsSigningService = new CmsSigningService();
        PdfSigningService pdfSigningService = new PdfSigningService(
                signingKeyProvider, certValidator, cmsSigningService
        );

        server = new RestServer(discoverer, auth, sessionManager, pdfSigningService);
        port = server.start(0); // 0 = random port
        client = HttpClient.newHttpClient();
    }

    @AfterEach
    void tearDown() {
        // HttpServer doesn't have a stop method easily accessible in test.
        // The JVM will exit after tests; this is fine for now.
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