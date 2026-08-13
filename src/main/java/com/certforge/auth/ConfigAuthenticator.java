package com.certforge.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

public class ConfigAuthenticator implements Authenticator {
    private final List<byte[]> validKeyBytes;

    public ConfigAuthenticator(List<String> validKeys) {
        this.validKeyBytes = validKeys.stream()
                .map(k -> k.getBytes(StandardCharsets.UTF_8))
                .toList();
    }

    @Override
    public boolean isValid(String apiKey) {
        if (validKeyBytes.isEmpty()) {
            return true;
        }
        if (apiKey == null) {
            return false;
        }
        byte[] candidateBytes = apiKey.getBytes(StandardCharsets.UTF_8);
        for (byte[] expectedBytes : validKeyBytes) {
            if (MessageDigest.isEqual(expectedBytes, candidateBytes)) {
                return true;
            }
        }
        return false;
    }
}
