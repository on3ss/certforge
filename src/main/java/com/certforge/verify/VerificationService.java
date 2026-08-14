package com.certforge.verify;

public interface VerificationService {
    VerificationResult verify(byte[] pdfBytes);
}
