package com.certforge.auth;

@FunctionalInterface
public interface Authenticator {
    boolean isValid(String apiKey);
}