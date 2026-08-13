package com.certforge.discovery;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

/**
 * Combines hard‑coded OS‑specific paths with the CERTFORGE_LIBRARIES environment variable.
 */
public class DefaultLibraryPathProvider implements LibraryPathProvider {

    private static final Logger LOG = Logger.getLogger(DefaultLibraryPathProvider.class.getName());

    @Override
    public List<String> getPaths() {
        List<String> paths = new ArrayList<>();
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            Collections.addAll(paths,
                    "C:\\SoftHSM2\\lib\\softhsm2-x64.dll",
                    "C:\\SoftHSM2\\lib\\softhsm2.dll",
                    "C:\\Windows\\System32\\eTPKCS11.dll",
                    "C:\\Windows\\System32\\ykcs11.dll",
                    "C:\\Windows\\System32\\opensc-pkcs11.dll"
            );
        } else if (os.contains("mac")) {
            Collections.addAll(paths,
                    "/usr/local/lib/softhsm/libsofthsm2.so",
                    "/usr/local/lib/libeTPkcs11.dylib",
                    "/usr/local/lib/ykcs11.dylib",
                    "/usr/local/lib/opensc-pkcs11.so"
            );
        } else { // linux
            Collections.addAll(paths,
                    "/usr/lib/softhsm/libsofthsm2.so",
                    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                    "/usr/lib/libeTPkcs11.so",
                    "/usr/lib/ykcs11.so",
                    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
            );
        }

        // Extend with environment variable
        String extra = System.getenv("CERTFORGE_LIBRARIES");
        if (extra != null && !extra.isBlank()) {
            for (String part : extra.split(",")) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    paths.add(trimmed);
                    LOG.fine(() -> "Added library path from CERTFORGE_LIBRARIES: " + trimmed);
                }
            }
        }
        return paths;
    }
}