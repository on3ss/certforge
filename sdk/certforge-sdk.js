/**
 * CertForge Gateway JavaScript/TypeScript Client SDK
 */
class CertForgeClient {
  /**
   * @param {string} baseUrl Gateway base URL (default: http://127.0.0.1:8443)
   * @param {string} apiKey API key for Bearer authentication
   */
  constructor(baseUrl = 'http://127.0.0.1:8443', apiKey = '') {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.apiKey = apiKey;
  }

  /**
   * @private
   */
  async getHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
    return headers;
  }

  /**
   * Health check endpoint
   */
  async health() {
    const res = await fetch(`${this.baseUrl}/health`);
    if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
    return await res.json();
  }

  /**
   * Discover auto-detected USB PKCS#11 hardware tokens
   */
  async listTokens() {
    const res = await fetch(`${this.baseUrl}/v1/tokens`, {
      headers: await this.getHeaders()
    });
    if (!res.ok) throw new Error(`Failed to list tokens: ${res.statusText}`);
    return await res.json();
  }

  /**
   * Open a PIN-protected session on a token
   * @param {string} tokenId
   * @param {string} pin
   */
  async openSession(tokenId, pin) {
    const res = await fetch(`${this.baseUrl}/v1/sessions`, {
      method: 'POST',
      headers: await this.getHeaders(),
      body: JSON.stringify({ tokenId, pin })
    });
    if (!res.ok) throw new Error(`Failed to open session: ${res.statusText}`);
    return await res.json();
  }

  /**
   * Close an active session
   * @param {string} sessionId
   */
  async closeSession(sessionId) {
    const res = await fetch(`${this.baseUrl}/v1/sessions/${sessionId}`, {
      method: 'DELETE',
      headers: await this.getHeaders()
    });
    if (!res.ok) throw new Error(`Failed to close session: ${res.statusText}`);
    return await res.json();
  }

  /**
   * List signing certificates available in session
   * @param {string} sessionId
   */
  async listCertificates(sessionId) {
    const res = await fetch(`${this.baseUrl}/v1/sessions/${sessionId}/certificates`, {
      headers: await this.getHeaders()
    });
    if (!res.ok) throw new Error(`Failed to list certificates: ${res.statusText}`);
    return await res.json();
  }

  /**
   * Sign a PDF document with optional visible signature appearance & template
   * @param {string} sessionId
   * @param {string} alias Certificate key alias
   * @param {string} pdfBase64 Base64-encoded input PDF
   * @param {Object} [options]
   * @param {string} [options.template] Named template defined in gateway.yml (e.g. 'standard')
   * @param {Object} [options.appearance] Visible signature appearance configuration
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

      body.appearance = app;
    }

    const res = await fetch(`${this.baseUrl}/v1/sessions/${sessionId}/jobs`, {
      method: 'POST',
      headers: await this.getHeaders(),
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`Signing job failed: ${res.statusText}`);
    return await res.json();
  }

  /**
   * Verify signature integrity of a signed PDF document
   * @param {string} pdfBase64 Base64-encoded signed PDF
   */
  async verify(pdfBase64) {
    const res = await fetch(`${this.baseUrl}/v1/verify`, {
      method: 'POST',
      headers: await this.getHeaders(),
      body: JSON.stringify({ document: pdfBase64 })
    });
    if (!res.ok) throw new Error(`Verification failed: ${res.statusText}`);
    return await res.json();
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CertForgeClient };
}
