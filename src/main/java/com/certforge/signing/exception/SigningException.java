package com.certforge.signing.exception;

public class SigningException extends Exception {
    public SigningException(String message) {
        super(message);
    }

    public SigningException(String message, Throwable cause) {
        super(message, cause);
    }
}