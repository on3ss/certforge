package com.certforge.discovery;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Token discovery implementation that scans PKCS#11 libraries.
 * Depends on a {@link LibraryPathProvider} to know where to look.
 */
public class Pkcs11TokenDiscoverer implements TokenDiscoverer {
    private static final Logger LOG = Logger.getLogger(Pkcs11TokenDiscoverer.class.getName());
    private static final long PROBE_TIMEOUT_SECONDS = 5;

    private final LibraryPathProvider pathProvider;

    public Pkcs11TokenDiscoverer(LibraryPathProvider pathProvider) {
        this.pathProvider = pathProvider;
    }

    @Override
    public List<TokenInfo> discover() {
        List<String> paths = pathProvider.getPaths();
        List<TokenInfo> allTokens = new ArrayList<>();

        for (String libPath : paths) {
            try {
                List<TokenInfo> tokens = Pkcs11Probe.probe(libPath, PROBE_TIMEOUT_SECONDS);
                allTokens.addAll(tokens);
            } catch (Exception e) {
                LOG.fine("Skipping " + libPath + ": " + e.getMessage());
            }
        }
        return allTokens;
    }
}