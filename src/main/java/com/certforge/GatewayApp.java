package com.certforge;

import com.certforge.audit.AuditLogger;
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
import com.certforge.verify.PdfVerificationService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GatewayApp {

    private static final Logger LOG = Logger.getLogger(GatewayApp.class.getName());
    private static final String VERSION = "0.1.0";

    private static SessionManager sessionManager;

    private static String defaultConfigPath() {
        return System.getProperty("user.home") + "/.certforge/gateway.yml";
    }

    public static void main(String[] args) throws Exception {
        Config config = loadConfig();

        AuditLogger auditLogger = new AuditLogger(config.auditPath());
        auditLogger.logStarted(VERSION);

        if (config.apiKeys().isEmpty()) {
            LOG.warning("SECURITY WARNING: No API keys configured! Gateway authentication is open.");
        } else {
            LOG.info("Authenticator initialized with " + config.apiKeys().size() + " API key(s)");
        }
        Authenticator authenticator = new ConfigAuthenticator(config.apiKeys());

        int port = resolvePort(config);

        sessionManager = new SessionManager(
                auditLogger,
                config.poolConfig(),
                config.sessionInactivityTimeout(),
                config.sessionMaxLifetime()
        );

        RestServer server = getRestServer(config, authenticator, auditLogger);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOG.info("Shutdown signal received. Stopping CertForge Gateway Application.");
            sessionManager.shutdown();
            auditLogger.logStopped();
        }));

        server.start(port);

        LOG.info("Ready. Press Ctrl+C to stop.");
        Thread.currentThread().join();
    }

    private static Config loadConfig() {
        String configPathEnv = System.getenv("CERTFORGE_CONFIG");
        Path configPath;
        if (configPathEnv != null && !configPathEnv.isBlank()) {
            configPath = Path.of(configPathEnv);
            LOG.fine("Config path set from environment variable CERTFORGE_CONFIG: " + configPath);
        } else {
            configPath = Path.of(defaultConfigPath());
            LOG.fine("Config path set to default location: " + configPath);
        }

        if (Files.exists(configPath)) {
            try {
                Config config = ConfigLoader.load(configPath);
                LOG.info("Configuration loaded from " + configPath);
                return config;
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Failed to parse config file " + configPath + ": " + e.getMessage(), e);
                LOG.info("Using built-in defaults");
                return new Config(8443, List.of(), 3600, 86400, Path.of("audit.log"), "info");
            }
        } else {
            LOG.info("No config file found at " + configPath + "; using built-in defaults.");
            return new Config(8443, List.of(), 3600, 86400, Path.of("audit.log"), "info");
        }
    }

    private static int resolvePort(Config config) {
        int port = config.port();
        String portEnv = System.getenv("CERTFORGE_PORT");
        if (portEnv != null && !portEnv.isBlank()) {
            try {
                port = Integer.parseInt(portEnv);
                LOG.info("Port overridden via CERTFORGE_PORT environment variable to " + port);
            } catch (NumberFormatException e) {
                LOG.log(Level.WARNING, "Invalid CERTFORGE_PORT: " + portEnv + "; falling back to " + port, e);
            }
        }
        return port;
    }

    private static RestServer getRestServer(Config config, Authenticator authenticator, AuditLogger auditLogger) {
        TokenDiscoverer discoverer = new Pkcs11TokenDiscoverer(
                new DefaultLibraryPathProvider(), auditLogger
        );

        SigningKeyProvider signingKeyProvider = new SigningKeyProvider(sessionManager, auditLogger);
        CertificateChainValidator certValidator = new CertificateChainValidator(auditLogger);
        CmsSigningService cmsSigningService = new CmsSigningService(auditLogger);
        PdfSigningService pdfSigningService = new PdfSigningService(
                signingKeyProvider, certValidator, cmsSigningService, auditLogger
        );

        PdfVerificationService pdfVerificationService = new PdfVerificationService(auditLogger);

        return new RestServer(
                discoverer, authenticator, sessionManager, pdfSigningService, auditLogger, pdfVerificationService, config.templateManager()
        );
    }
}