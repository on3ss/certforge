package com.certforge;

import com.certforge.auth.ConfigAuthenticator;
import com.certforge.auth.Authenticator;
import com.certforge.config.Config;
import com.certforge.config.ConfigLoader;
import com.certforge.discovery.DefaultLibraryPathProvider;
import com.certforge.discovery.Pkcs11TokenDiscoverer;
import com.certforge.discovery.TokenDiscoverer;
import com.certforge.server.RestServer;
import com.certforge.session.SessionManager;
import com.certforge.signing.PdfSigningService;
import com.certforge.signing.certificate.CertificateChainValidator;
import com.certforge.signing.cms.CmsSigningService;
import com.certforge.signing.crypto.SigningKeyProvider;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GatewayApp {

    private static final Logger LOG = Logger.getLogger(GatewayApp.class.getName());

    private static String defaultConfigPath() {
        return System.getProperty("user.home") + "/.certforge/gateway.yml";
    }

    public static void main(String[] args) throws Exception {
        LOG.info("Starting CertForge Gateway Application...");

        // 1. Determine config file path
        String configPathEnv = System.getenv("CERTFORGE_CONFIG");
        Path configPath;
        if (configPathEnv != null && !configPathEnv.isBlank()) {
            configPath = Path.of(configPathEnv);
            LOG.fine("Config path set from environment variable CERTFORGE_CONFIG: " + configPath);
        } else {
            configPath = Path.of(defaultConfigPath());
            LOG.fine("Config path set to default location: " + configPath);
        }

        // 2. Load configuration or use built-in defaults
        Config config;
        if (Files.exists(configPath)) {
            config = ConfigLoader.load(configPath);
            LOG.info("Configuration loaded from " + configPath);
        } else {
            config = new Config(8443, List.of(), 3600, 86400, Path.of("audit.log"), "info");
            LOG.info("No config file found at " + configPath + "; using built-in defaults.");
        }

        // 3. Port override via environment variable
        int port = config.getPort();
        String portEnv = System.getenv("CERTFORGE_PORT");
        if (portEnv != null && !portEnv.isBlank()) {
            try {
                port = Integer.parseInt(portEnv);
                LOG.info("Port overridden via CERTFORGE_PORT environment variable to " + port);
            } catch (NumberFormatException e) {
                LOG.log(Level.WARNING, "Invalid CERTFORGE_PORT environment variable value: " + portEnv + "; falling back to port " + port, e);
            }
        }

        // 4. Authentication
        Authenticator authenticator = new ConfigAuthenticator(config.getApiKeys());
        LOG.info("Authenticator initialized with " + config.getApiKeys().size() + " API key(s)");

        // 5. Session management
        RestServer server = getRestServer(authenticator);
        server.start(port);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOG.info("Shutdown signal received. Stopping CertForge Gateway Application.");
        }));

        LOG.info("Ready. Press Ctrl+C to stop.");
        Thread.currentThread().join();
    }

    private static RestServer getRestServer(Authenticator authenticator) {
        SessionManager sessionManager = new SessionManager();

        // 6. Assemble the gateway
        TokenDiscoverer discoverer = new Pkcs11TokenDiscoverer(new DefaultLibraryPathProvider());

        // 7. Signing service
        SigningKeyProvider signingKeyProvider = new SigningKeyProvider(sessionManager);
        CertificateChainValidator certValidator = new CertificateChainValidator();
        CmsSigningService cmsSigningService = new CmsSigningService();
        PdfSigningService pdfSigningService = new PdfSigningService(
                signingKeyProvider, certValidator, cmsSigningService
        );

        return new RestServer(discoverer, authenticator, sessionManager, pdfSigningService);
    }
}