package com.certforge.config;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

public class Config {
    private final int port;
    private final List<String> apiKeys;
    private final int sessionInactivityTimeout;
    private final int sessionMaxLifetime;
    private final Path auditPath;
    private final String loggingLevel;

    // Package-private constructor – created by ConfigLoader
    public Config(int port, List<String> apiKeys, int sessionInactivityTimeout,
           int sessionMaxLifetime, Path auditPath, String loggingLevel) {
        this.port = port;
        this.apiKeys = Collections.unmodifiableList(apiKeys);
        this.sessionInactivityTimeout = sessionInactivityTimeout;
        this.sessionMaxLifetime = sessionMaxLifetime;
        this.auditPath = auditPath;
        this.loggingLevel = loggingLevel;
    }

    public int getPort() {
        return port;
    }

    public List<String> getApiKeys() {
        return apiKeys;
    }

    public int getSessionInactivityTimeout() {
        return sessionInactivityTimeout;
    }

    public int getSessionMaxLifetime() {
        return sessionMaxLifetime;
    }

    public Path getAuditPath() {
        return auditPath;
    }

    public String getLoggingLevel() {
        return loggingLevel;
    }
}