package com.certforge.signing;

import com.certforge.signing.exception.InvalidCertificateException;
import com.certforge.signing.exception.PdfSigningException;
import com.certforge.signing.exception.SigningKeyNotFoundException;

public interface SigningService {
    byte[] signPdf(String sessionId, String alias, byte[] pdfBytes)
            throws PdfSigningException, SigningKeyNotFoundException, InvalidCertificateException;
}
