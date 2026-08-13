package com.certforge.signing.exception;

public class PdfSigningException extends SigningException {
    public PdfSigningException(String message) {
        super(message);
    }

    public PdfSigningException(String message, Throwable cause) {
        super(message, cause);
    }
}