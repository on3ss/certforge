package com.certforge.session;

public class CertificateInfo {
    private final String alias;
    private final String subject;
    private final String issuer;
    private final String serialNumber;
    private final String notBefore;
    private final String notAfter;
    private final String keyType;
    private final int keySize;

    public CertificateInfo(String alias, String subject, String issuer,
                           String serialNumber, String notBefore, String notAfter,
                           String keyType, int keySize) {
        this.alias = alias;
        this.subject = subject;
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.keyType = keyType;
        this.keySize = keySize;
    }

    public String getAlias() { return alias; }
    public String getSubject() { return subject; }
    public String getIssuer() { return issuer; }
    public String getSerialNumber() { return serialNumber; }
    public String getNotBefore() { return notBefore; }
    public String getNotAfter() { return notAfter; }
    public String getKeyType() { return keyType; }
    public int getKeySize() { return keySize; }
}
