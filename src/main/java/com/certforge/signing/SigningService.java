package com.certforge.signing;

import com.certforge.signing.appearance.SignatureAppearance;
import com.certforge.signing.exception.InvalidCertificateException;
import com.certforge.signing.exception.PdfSigningException;
import com.certforge.signing.exception.SigningKeyNotFoundException;

public interface SigningService {
    default byte[] signPdf(String sessionId, String alias, byte[] pdfBytes)
            throws PdfSigningException, SigningKeyNotFoundException, InvalidCertificateException {
        return signPdf(sessionId, alias, pdfBytes, null);
    }

    byte[] signPdf(String sessionId, String alias, byte[] pdfBytes, SignatureAppearance appearance)
            throws PdfSigningException, SigningKeyNotFoundException, InvalidCertificateException;
}
