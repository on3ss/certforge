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
        this.apiKeys = Collections.unmodifiableList(apiKeys);
        this.sessionInactivityTimeout = sessionInactivityTimeout;
        this.sessionMaxLifetime = sessionMaxLifetime;
        this.auditPath = auditPath;
        this.loggingLevel = loggingLevel;
        this.poolConfig = poolConfig != null ? poolConfig : PoolConfig.defaultConfig();
        this.templateManager = templateManager != null ? templateManager : new TemplateManager();
        this.templatesDir = templatesDir != null ? templatesDir : Path.of("templates");
    }
}