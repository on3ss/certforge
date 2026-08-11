package com.certforge.discovery;

import java.util.List;

/**
 * Provides a list of PKCS#11 library file paths.
 * Implementations can be OS‑specific or extend with environment variables.
 */
@FunctionalInterface
public interface LibraryPathProvider {
    List<String> getPaths();
}
