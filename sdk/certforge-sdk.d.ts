export interface Rectangle {
    x: number;
    y: number;
    width: number;
    height: number;
}

export interface SignatureAppearanceOptions {
    type?: 'none' | 'text' | 'image' | 'text_image';
    page?: number;
    position?: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' | 'center';
    pagePosition?: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' | 'center';
    searchText?: string;
    searchPosition?: 'above' | 'below' | 'left' | 'right' | 'over';
    padding?: number;
    rectangle?: Rectangle;
    textLines?: string[];
    fontSize?: number;
    imageBase64?: string;
    reason?: string;
    location?: string;
}

export interface SignPdfOptions {
    template?: string;
    appearance?: SignatureAppearanceOptions;
}

export interface HealthResponse {
    status: string;
}

export interface TokenInfo {
    id: string;
    label: string;
    manufacturer: string;
    serial: string;
    libraryPath: string;
    slotId: number;
}

export interface TokensResponse {
    tokens: TokenInfo[];
}

export interface OpenSessionResponse {
    sessionId: string;
}

export interface CloseSessionResponse {
    status: string;
}

export interface CertificateInfo {
    alias: string;
    subject: string;
    issuer: string;
    serialNumber: string;
    notBefore: string;
    notAfter: string;
    keyType: string;
    keySize: number;
}

export interface CertificatesResponse {
    certificates: CertificateInfo[];
}

export interface SignPdfResponse {
    jobId: string;
    status: string;
    document: {
        data: string;
        filename: string;
    };
}

export interface SignatureVerificationDetail {
    signer: string;
    signedAt: string;
    integrity: string;
    certificateValid: boolean;
    certificateExpiry: string;
}

export interface VerifyResponse {
    valid: boolean;
    signatures: SignatureVerificationDetail[];
}

export interface CertForgeError extends Error {
    statusCode?: number;
    errorCode?: string;
    timestamp?: string;
}

export class CertForgeClient {
    constructor(baseUrl?: string, apiKey?: string, timeoutMs?: number);

    health(): Promise<HealthResponse>;

    listTokens(): Promise<TokensResponse>;

    openSession(tokenId: string, pin: string): Promise<OpenSessionResponse>;

    closeSession(sessionId: string): Promise<CloseSessionResponse>;

    listCertificates(sessionId: string): Promise<CertificatesResponse>;

    signPdf(
        sessionId: string,
        alias: string,
        pdfBase64: string,
        options?: SignPdfOptions
    ): Promise<SignPdfResponse>;

    verify(pdfBase64: string): Promise<VerifyResponse>;
}