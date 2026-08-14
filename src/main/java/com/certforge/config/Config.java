package com.certforge.config;

import com.certforge.pool.PoolConfig;
import com.certforge.signing.appearance.TemplateManager;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

public record Config(int port, List<String> apiKeys, int sessionInactivityTimeout, int sessionMaxLifetime,
                     Path auditPath, String loggingLevel, PoolConfig poolConfig,
                     TemplateManager templateManager, Path templatesDir) {

    public Config(int port, List<String> apiKeys, int sessionInactivityTimeout,
                  int sessionMaxLifetime, Path auditPath, String loggingLevel) {
        this(port, apiKeys, sessionInactivityTimeout, sessionMaxLifetime, auditPath, loggingLevel, PoolConfig.defaultConfig(), new TemplateManager(), Path.of("templates"));
    }

    public Config(int port, List<String> apiKeys, int sessionInactivityTimeout,
                  int sessionMaxLifetime, Path auditPath, String loggingLevel, PoolConfig poolConfig) {
        this(port, apiKeys, sessionInactivityTimeout, sessionMaxLifetime, auditPath, loggingLevel, poolConfig, new TemplateManager(), Path.of("templates"));
    }

    public Config(int port, List<String> apiKeys, int sessionInactivityTimeout,
                  int sessionMaxLifetime, Path auditPath, String loggingLevel, PoolConfig poolConfig,
                  TemplateManager templateManager, Path templatesDir) {
        this.port = port;
        this.apiKeys = apiKeys != null ? List.copyOf(apiKeys) : Collections.emptyList();
        this.sessionInactivityTimeout = sessionInactivityTimeout;
        this.sessionMaxLifetime = sessionMaxLifetime;
        this.auditPath = auditPath;
        this.loggingLevel = loggingLevel;
        this.poolConfig = poolConfig != null ? poolConfig : PoolConfig.defaultConfig();
        this.templateManager = templateManager != null ? templateManager : new TemplateManager();
        this.templatesDir = templatesDir != null ? templatesDir : Path.of("templates");
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private int port = 8443;
        private List<String> apiKeys = List.of();
        private int sessionInactivityTimeout = 3600;
        private int sessionMaxLifetime = 86400;
        private Path auditPath = Path.of("audit.log");
        private String loggingLevel = "info";
        private PoolConfig poolConfig = PoolConfig.defaultConfig();
        private TemplateManager templateManager = new TemplateManager();
        private Path templatesDir = Path.of("templates");

        public Builder port(int port) { this.port = port; return this; }
        public Builder apiKeys(List<String> apiKeys) { this.apiKeys = apiKeys; return this; }
        public Builder sessionInactivityTimeout(int timeout) { this.sessionInactivityTimeout = timeout; return this; }
        public Builder sessionMaxLifetime(int lifetime) { this.sessionMaxLifetime = lifetime; return this; }
        public Builder auditPath(Path path) { this.auditPath = path; return this; }
        public Builder loggingLevel(String level) { this.loggingLevel = level; return this; }
        public Builder poolConfig(PoolConfig poolConfig) { this.poolConfig = poolConfig; return this; }
        public Builder templateManager(TemplateManager templateManager) { this.templateManager = templateManager; return this; }
        public Builder templatesDir(Path templatesDir) { this.templatesDir = templatesDir; return this; }

        public Config build() {
            return new Config(port, apiKeys, sessionInactivityTimeout, sessionMaxLifetime,
                    auditPath, loggingLevel, poolConfig, templateManager, templatesDir);
        }
    }
}