/**
 * CertForge Gateway JavaScript/TypeScript Client SDK
 *
 * Example usage:
 *   const client = new CertForgeClient('http://127.0.0.1:8443', 'your-api-key');
 *   const { tokens } = await client.listTokens();
 *   const { sessionId } = await client.openSession(tokens[0].id, '1234');
 *   const { certificates } = await client.listCertificates(sessionId);
 *   const signedPdf = await client.signPdf(sessionId, certificates[0].alias, pdfBase64, {
 *       template: 'standard'
 *   });
 */
class CertForgeClient {
    /**
     * @param {string} baseUrl Gateway base URL (default: http://127.0.0.1:8443)
     * @param {string} apiKey API key for Bearer authentication
     * @param {number} timeoutMs Request timeout in milliseconds (default: 30000)
     */
    constructor(baseUrl = 'http://127.0.0.1:8443', apiKey = '', timeoutMs = 30000) {
        this.baseUrl = baseUrl.replace(/\/+$/, '');
        this.apiKey = apiKey;
        this.timeoutMs = timeoutMs;
    }

    /**
     * @private
     */
    async getHeaders() {
        const headers = {'Content-Type': 'application/json'};
        if (this.apiKey) {
            headers['Authorization'] = `Bearer ${this.apiKey}`;
        }
        return headers;
    }

    /**
     * @private
     * Fetch with timeout support
     */
    async _fetch(url, options = {}) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            return await fetch(url, {...options, signal: controller.signal});
        } catch (err) {
            if (err.name === 'AbortError') {
                throw new Error(`Request timed out after ${this.timeoutMs}ms`);
            }
            throw err;
        } finally {
            clearTimeout(timeout);
        }
    }

    /**
     * @private
     * Parse response or throw structured error
     */
    async _handleResponse(res, fallbackMessage = 'Request failed') {
        if (!res.ok) {
            let errorBody = {};
            try {
                errorBody = await res.json();
            } catch (_) {
                // Response is not JSON
            }
            const message = errorBody.message || `${fallbackMessage}: ${res.status} ${res.statusText}`;
            const error = new Error(message);
            error.statusCode = res.status;
            error.errorCode = errorBody.error;
            error.timestamp = errorBody.timestamp;
            throw error;
        }
        return await res.json();
    }

    /**
     * Health check endpoint
     * @returns {Promise<{status: string}>}
     */
    async health() {
        const res = await this._fetch(`${this.baseUrl}/health`);
        return this._handleResponse(res, 'Health check failed');
    }

    /**
     * Discover auto-detected USB PKCS#11 hardware tokens
     * @returns {Promise<{tokens: Array}>}
     */
    async listTokens() {
        const res = await this._fetch(`${this.baseUrl}/v1/tokens`, {
            headers: await this.getHeaders()
        });
        return this._handleResponse(res, 'Failed to list tokens');
    }

    /**
     * Open a PIN-protected session on a token
     * @param {string} tokenId Token ID from listTokens()
     * @param {string} pin Token PIN
     * @returns {Promise<{sessionId: string}>}
     */
    async openSession(tokenId, pin) {
        const res = await this._fetch(`${this.baseUrl}/v1/sessions`, {
            method: 'POST',
            headers: await this.getHeaders(),
            body: JSON.stringify({tokenId, pin})
        });
        return this._handleResponse(res, 'Failed to open session');
    }

    /**
     * Close an active session
     * @param {string} sessionId Session ID from openSession()
     * @returns {Promise<{status: string}>}
     */
    async closeSession(sessionId) {
        const res = await this._fetch(`${this.baseUrl}/v1/sessions/${sessionId}`, {
            method: 'DELETE',
            headers: await this.getHeaders()
        });
        return this._handleResponse(res, 'Failed to close session');
    }

    /**
     * List signing certificates available in session
     * @param {string} sessionId Session ID from openSession()
     * @returns {Promise<{certificates: Array}>}
     */
    async listCertificates(sessionId) {
        const res = await this._fetch(`${this.baseUrl}/v1/sessions/${sessionId}/certificates`, {
            headers: await this.getHeaders()
        });
        return this._handleResponse(res, 'Failed to list certificates');
    }

    /**
     * Sign a PDF document with optional visible signature appearance & template
     *
     * @param {string} sessionId Active session ID
     * @param {string} alias Certificate key alias from listCertificates()
     * @param {string} pdfBase64 Base64-encoded input PDF
     * @param {Object} [options] Optional signing options
     * @param {string} [options.template] Named template defined in gateway.yml (e.g. 'standard')
     * @param {Object} [options.appearance] Visible signature appearance configuration
     * @param {string} [options.appearance.type] 'none' | 'text' | 'image' | 'text_image'
     * @param {number} [options.appearance.page] 0-based page index
     * @param {string} [options.appearance.position] 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' | 'center'
     * @param {string} [options.appearance.searchText] Text to search for in PDF (e.g. '{{signature}}')
     * @param {string} [options.appearance.searchPosition] 'above' | 'below' | 'left' | 'right' | 'over'
     * @param {number} [options.appearance.padding] Inner padding in PDF points
     * @param {Object} [options.appearance.rectangle] Absolute rectangle {x, y, width, height}
     * @param {string[]} [options.appearance.textLines] Text lines to render
     * @param {number} [options.appearance.fontSize] Font size in points
     * @param {string} [options.appearance.imageBase64] Base64-encoded image (PNG/JPEG)
     * @param {string} [options.appearance.reason] Signature reason
     * @param {string} [options.appearance.location] Signature location
     * @returns {Promise<{jobId: string, status: string, document: {data: string, filename: string}}>}
     */
    async signPdf(sessionId, alias, pdfBase64, options = {}) {
        const body = {
            document: pdfBase64,
            alias: alias
        };

        if (options.template) {
            body.template = options.template;
        }

        if (options.appearance) {
            const app = options.appearance;

            body.appearanceType = app.type || 'text';
            body.appearancePage = app.page || 0;

            if (app.position || app.pagePosition) {
                body.appearancePosition = app.position || app.pagePosition;
            }
            if (app.searchText) {
                body.appearanceSearchText = app.searchText;
            }
            if (app.searchPosition) {
                body.appearanceSearchPosition = app.searchPosition;
            }
            if (app.padding) {
                body.appearancePadding = app.padding;
            }
            if (app.rectangle) {
                body.appearanceX = app.rectangle.x || 0;
                body.appearanceY = app.rectangle.y || 0;
                body.appearanceWidth = app.rectangle.width || 200;
                body.appearanceHeight = app.rectangle.height || 50;
            }
            if (app.textLines) {
                body.appearanceTextLines = app.textLines;
            }
            if (app.fontSize) {
                body.appearanceFontSize = app.fontSize;
            }
            if (app.imageBase64) {
                body.appearanceImageBase64 = app.imageBase64;
            }
            if (app.reason) {
                body.appearanceReason = app.reason;
            }
            if (app.location) {
                body.appearanceLocation = app.location;
            }
        }

        const res = await this._fetch(`${this.baseUrl}/v1/sessions/${sessionId}/jobs`, {
            method: 'POST',
            headers: await this.getHeaders(),
            body: JSON.stringify(body)
        });
        return this._handleResponse(res, 'Signing job failed');
    }

    /**
     * Verify signature integrity of a signed PDF document
     * @param {string} pdfBase64 Base64-encoded signed PDF
     * @returns {Promise<{valid: boolean, signatures: Array}>}
     */
    async verify(pdfBase64) {
        const res = await this._fetch(`${this.baseUrl}/v1/verify`, {
            method: 'POST',
            headers: await this.getHeaders(),
            body: JSON.stringify({document: pdfBase64})
        });
        return this._handleResponse(res, 'Verification failed');
    }
}

// Node.js CommonJS export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {CertForgeClient};
}

// Browser global export
if (typeof window !== 'undefined') {
    window.CertForgeClient = CertForgeClient;
}