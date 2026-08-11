package com.certforge.discovery;

import java.util.List;

/**
 * Any mechanism that can discover cryptographic tokens.
 * This is the primary extension point.
 */
@FunctionalInterface
public interface TokenDiscoverer {
    List<TokenInfo> discover();
}
