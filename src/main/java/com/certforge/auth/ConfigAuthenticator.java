package com.certforge.auth;

import java.util.List;

public class ConfigAuthenticator implements Authenticator{
    private final List<String> validKeys;

    public ConfigAuthenticator(List<String> validKeys) {
        this.validKeys = List.copyOf(validKeys);
    }

    @Override
    public boolean isValid(String apiKey){
        if (validKeys.isEmpty()) {
            return true;
        }
        return validKeys.contains(apiKey);
    }
}
