package com.certforge.session;

public record CertificateInfo(String alias, String subject, String issuer, String serialNumber, String notBefore,
                              String notAfter, String keyType, int keySize) {
}
