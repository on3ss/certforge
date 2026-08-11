package com.certforge;

import com.certforge.config.Config;
import com.certforge.config.ConfigLoader;
import com.certforge.discovery.DefaultLibraryPathProvider;
import com.certforge.discovery.Pkcs11TokenDiscoverer;
import com.certforge.discovery.TokenDiscoverer;
import com.certforge.server.RestServer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Logger;

public class GatewayApp {

    private static final Logger LOG = Logger.getLogger(GatewayApp.class.getName());

    private static String defaultConfigPath() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            return "C:\\ProgramData\\CertForge\\gateway.yml";
        } else if (os.contains("mac")) {
            return "/Library/Application Support/CertForge/gateway.yml";
        } else { // linux and other Unix
            return "/etc/certforge/gateway.yml";
        }
    }

    public static void main(String[] args) throws Exception {
        // 1. Determine config file path
        String configPathEnv = System.getenv("CERTFORGE_CONFIG");
        Path configPath;
        if (configPathEnv != null && !configPathEnv.isBlank()) {
            configPath = Path.of(configPathEnv);
        } else {
            configPath = Path.of(defaultConfigPath());
        }

        // 2. Load configuration or use built-in defaults
        Config config;
        if (Files.exists(configPath)) {
            config = ConfigLoader.load(configPath);
            LOG.info("Configuration loaded from " + configPath);
        } else {
            // Built‑in defaults
            config = new Config(8443, List.of(), 3600, 86400, Path.of("audit.log"), "info");
            LOG.info("No config file found at " + configPath + "; using built‑in defaults.");
        }

        // 3. Port override via environment variable
        int port = config.getPort();
        String portEnv = System.getenv("CERTFORGE_PORT");
        if (portEnv != null && !portEnv.isBlank()) {
            port = Integer.parseInt(portEnv);
        }

        // 4. Assemble the gateway
        TokenDiscoverer discoverer = new Pkcs11TokenDiscoverer(new DefaultLibraryPathProvider());
        RestServer server = new RestServer(discoverer);
        server.start(port);

        LOG.info("Ready. Press Ctrl+C to stop.");
        Thread.currentThread().join();
    }
}