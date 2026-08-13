package com.certforge.signing.exception;

public class TokenSigningException extends SigningException {
    public TokenSigningException(String message) {
        super(message);
    }

    public TokenSigningException(String message, Throwable cause) {
        super(message, cause);
    }
}