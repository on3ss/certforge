package com.certforge.config;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

public record Config(int port, List<String> apiKeys, int sessionInactivityTimeout, int sessionMaxLifetime,
                     Path auditPath, String loggingLevel) {
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
}