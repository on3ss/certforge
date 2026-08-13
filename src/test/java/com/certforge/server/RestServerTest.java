package com.certforge.server;

import com.certforge.audit.AuditLogger;
import com.certforge.auth.Authenticator;
import com.certforge.discovery.TokenDiscoverer;
import com.certforge.discovery.TokenInfo;
import com.certforge.session.SessionManager;
import com.certforge.signing.PdfSigningService;
import com.certforge.signing.certificate.CertificateChainValidator;
import com.certforge.signing.cms.CmsSigningService;
import com.certforge.signing.crypto.SigningKeyProvider;
import com.certforge.verify.PdfVerificationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RestServerTest {

    @TempDir
    Path tempDir;

    private RestServer server;
    private int port;
    private HttpClient client;
    private AuditLogger auditLogger;
    private SessionManager sessionManager;

    @BeforeEach
    void setUp() throws IOException {
        auditLogger = new AuditLogger(tempDir.resolve("audit.log"));

        Authenticator auth = apiKey -> apiKey.equals("good-key");

        TokenDiscoverer discoverer = () -> List.of(
                new TokenInfo("slot-1", "TestToken", "TestManuf", "1234",
                        "/lib/test.so", 1L)
        );

        sessionManager = new SessionManager(auditLogger);

        SigningKeyProvider signingKeyProvider = new SigningKeyProvider(sessionManager, auditLogger);
        CertificateChainValidator certValidator = new CertificateChainValidator(auditLogger);
        CmsSigningService cmsSigningService = new CmsSigningService(auditLogger);
        PdfSigningService pdfSigningService = new PdfSigningService(
                signingKeyProvider, certValidator, cmsSigningService, auditLogger
        );
        PdfVerificationService pdfVerificationService = new PdfVerificationService(auditLogger);

        server = new RestServer(
                discoverer, auth, sessionManager, pdfSigningService, auditLogger, pdfVerificationService
        );
        port = server.start(0);
        client = HttpClient.newHttpClient();
    }

    @AfterEach
    void tearDown() {
        sessionManager.shutdown();
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
    void verifyEndpointReturns400ForMissingDocument() throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/v1/verify"))
                .header("Authorization", "Bearer good-key")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(400, response.statusCode());
    }

    @Test
    void verifyEndpointReturns400ForInvalidBase64() throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/v1/verify"))
                .header("Authorization", "Bearer good-key")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"document\":\"!!!not-base64!!!\"}"))
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(400, response.statusCode());
    }
}