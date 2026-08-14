package com.certforge.discovery;

import com.certforge.audit.AuditLogger;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Token discovery implementation that scans PKCS#11 libraries.
 * Depends on a {@link LibraryPathProvider} to know where to look.
 */
public class Pkcs11TokenDiscoverer implements TokenDiscoverer {
    private static final Logger LOG = Logger.getLogger(Pkcs11TokenDiscoverer.class.getName());
    private static final long PROBE_TIMEOUT_SECONDS = 5;

    private final LibraryPathProvider pathProvider;
    private final AuditLogger auditLogger;

    public Pkcs11TokenDiscoverer(LibraryPathProvider pathProvider, AuditLogger auditLogger) {
        this.pathProvider = Objects.requireNonNull(pathProvider, "pathProvider cannot be null");
        this.auditLogger = Objects.requireNonNull(auditLogger, "auditLogger cannot be null");
    }

    @Override
    public List<TokenInfo> discover() {
        List<String> paths = pathProvider.getPaths();
        List<TokenInfo> allTokens = new ArrayList<>();

        LOG.fine(() -> "Scanning " + paths.size() + " library path(s) for PKCS#11 tokens...");
        auditLogger.logDiscoveryStarted(paths.size());

        for (String libPath : paths) {
            try {
                List<TokenInfo> tokens = Pkcs11Probe.probe(libPath, PROBE_TIMEOUT_SECONDS);
                if (!tokens.isEmpty()) {
                    LOG.fine(() -> "Found " + tokens.size() + " token(s) in library " + libPath);
                    auditLogger.logLibraryProbed(libPath, "success");

                    for (TokenInfo token : tokens) {
                        auditLogger.logTokenFound(token.id(), token.label(), token.serial());
                    }
                } else {
                    auditLogger.logLibraryProbed(libPath, "no_tokens");
                }
                allTokens.addAll(tokens);
            } catch (Exception e) {
                LOG.fine(() -> "Skipping " + libPath + ": " + e.getMessage());
                auditLogger.logLibraryProbed(libPath, "failed: " + e.getMessage());
            }
        }

        LOG.fine(() -> "Token discovery complete. Total tokens found: " + allTokens.size());
        auditLogger.logDiscoveryCompleted(allTokens.size());
        return allTokens;
    }
}