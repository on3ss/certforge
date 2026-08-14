# CertForge Gateway

**Plug in your USB token. It auto-detects. Your application signs PDFs via REST API. No cloud. No config. No compromise.**

CertForge Gateway is a lightweight native service that runs on Windows, macOS, and Linux. It bridges software applications to USB hardware security tokens for PDF digital signing. It exposes a local REST API. It has no graphical interface. Tokens are auto-detected — no configuration required.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Visual Signatures & Positioning](#visual-signatures--positioning)
- [Template System](#template-system)
- [Client SDK (JS/TS)](#client-sdk-jsts)
- [Configuration](#configuration)
- [Token Support](#token-support)
- [Security Model](#security-model)
- [Development & Testing](#development--testing)
- [License](#license)

---

## Features

- **Zero-config token discovery** — scans known PKCS#11 library paths automatically
- **Session management** — PIN-based sessions with inactivity and max lifetime expiry
- **Cryptographic & Visual PDF signing** — PAdES Baseline B using token-backed private keys
- **Flexible visual positioning** — absolute coordinates, page relative anchors (`top-left`, `top-right`, `bottom-left`, `bottom-right`, `center`), and document-wide text search (`appearanceSearchText`)
- **Relative search placement** — position signature box `above`, `below`, `left`, `right`, or `over` matching search text
- **Automatic cutoff prevention** — page boundary clamping keeps visual signatures inside visible margins
- **Reusable appearance templates** — YAML-configured named templates with dynamic variable placeholders (`{signer}`, `{date}`, `{reason}`, `{location}`)
- **Signature verification** — document integrity and certificate validation
- **Append-only audit logging** — thread-safe JSON logs with daily rotation
- **API key authentication** — Bearer token on all `/v1/*` endpoints
- **Private keys never leave the token** — local localhost operation only

---

## Architecture

```
┌──────────────────────────────────────────┐
│          Host Machine                    │
│                                          │
│  Business Application ──► localhost:8443 │
│                                  │       │
│                             CertForge    │
│                             Gateway      │
│                             (Service)    │
│                                  │       │
│                              Auto-detect │
│                              all tokens  │
│                                  │       │
│                    ┌─────────────┴──────┐│
│                    │                    ││
│                 USB Token        SoftHSM2│
│                 (DigiCert)        (dev)  │
└──────────────────────────────────────────┘
```

### Components

| Component | Responsibility |
|-----------|---------------|
| `discovery` | JNA-based PKCS#11 library scanning and token detection |
| `session` | SunPKCS11-based session management with PIN |
| `signing` | Cryptographic CMS & PDFBox 3.x visual appearance stream generation |
| `signing.appearance` | `SignatureAppearance`, `TemplateManager`, `AppearanceStreamBuilder`, text search finder |
| `verify` | Signature verification (CMS + PDF byte range) |
| `audit` | Append-only JSON audit logging |
| `auth` | API key authentication |
| `config` | YAML configuration loading |
| `server` | JDK HttpServer REST API & JSON serialization |

---

## Requirements

- **Java 25+** (JDK)
- **Gradle 9.x** (for building)
- **PKCS#11 token** (SoftHSM2 for development, hardware token for production)
- **Windows / macOS / Linux**

---

## Quick Start

### 1. Build

```bash
./gradlew build
```

Produces executable Fat JAR: `build/libs/certforge-gateway-0.1.0-all.jar`

### 2. Create Configuration

Place `gateway.yml` in `~/.certforge/gateway.yml`:

```yaml
gateway:
  port: 8443
  apiKeys:
    - "sk_your_api_key_here"

sessions:
  inactivityTimeout: 3600    # seconds
  maxLifetime: 86400         # seconds

templatesDir: "~/.certforge/templates"

templates:
  standard:
    type: "text"
    positionType: "pagePosition"
    pagePosition: "bottom-right"
    width: 220
    height: 45
    fontSize: 9
    padding: 6
    textLines:
      - "Digitally signed by {signer}"
      - "Date: {date}"
      - "Reason: {reason}"

audit:
  path: "~/.certforge/audit.log"

logging:
  level: "info"
```

### 3. Run

```bash
java --enable-native-access=ALL-UNNAMED -jar build/libs/certforge-gateway-0.1.0-all.jar
```

---

## API Reference

### Base URL & Auth

- **Base URL**: `http://127.0.0.1:8443/v1`
- **Auth Header**: `Authorization: Bearer <api-key>`

### Endpoints

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | `/health` | Health check | No |
| GET | `/v1/tokens` | List detected USB/PKCS#11 tokens | Yes |
| POST | `/v1/sessions` | Open session with PIN | Yes |
| GET | `/v1/sessions/{id}/certificates` | List certificates in session | Yes |
| POST | `/v1/sessions/{id}/jobs` | Sign PDF (invisible or visible appearance) | Yes |
| DELETE | `/v1/sessions/{id}` | Close session | Yes |
| POST | `/v1/verify` | Verify signed PDF | Yes |

---

## Visual Signatures & Positioning

CertForge Gateway supports rich visual signature widget appearances rendered directly onto target PDF pages.

### 1. Appearance Types (`appearanceType`)
- **`none`** *(default)*: Invisible cryptographic signature.
- **`text`**: Rendered multiline text (Helvetica font).
- **`image`**: Base64-encoded PNG/JPEG signature badge or seal.
- **`text_image`**: Side-by-side logo icon and metadata text.

### 2. Positioning Modes

#### A. Document-Wide Text Search (`appearanceSearchText` & `appearanceSearchPosition`)
Scans all document pages for a target string (e.g. `"Treasury Officer"`), detects the exact page and coordinates, and places the signature box relative to the text:
- **`appearanceSearchPosition`**:
  - **`"above"`** *(default)*: Positioned directly above the search text.
  - **`"below"`**: Positioned directly below the search text.
  - **`"left"`**: Positioned directly to the left of the search text.
  - **`"right"`**: Positioned directly to the right of the search text.
  - **`"over"`**: Overlay on top of search text.

#### B. Page Relative Anchors (`appearancePosition`)
Anchors the signature box relative to target page bounds (`0.5 in` default margin):
- `"top-left"`, `"top-right"`, `"bottom-left"`, `"bottom-right"`, `"center"`

#### C. Absolute Coordinates (`appearanceX`, `appearanceY`, `appearanceWidth`, `appearanceHeight`)
Exact lower-left origin coordinates in PDF points on target `appearancePage` (0-based).

### 3. Padding & Edge Clamping (`appearancePadding`)
- **Inner Padding**: Inset padding (default `6pt`) for text lines and images inside the signature box.
- **Edge Clamping**: Automatic page boundary clamping ($15\text{pt}$ margin) ensures signature widgets are never cut off at page margins.

---

## Template System

Pre-configure appearance templates in `gateway.yml` under the `templates:` section.

### Dynamic Placeholders
- `{signer}` — Alias / Certificate Common Name
- `{date}` — System ISO-8601 signing timestamp
- `{reason}` — Signing reason string
- `{location}` — Signing location string

### Example Template Sign Job
```bash
curl -X POST http://127.0.0.1:8443/v1/sessions/<SESSION_ID>/jobs \
  -H "Authorization: Bearer sk_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "document": "<BASE64_PDF>",
    "alias": "rsaKey",
    "template": "standard",
    "appearanceSearchText": "Treasury Officer",
    "appearanceSearchPosition": "above",
    "reason": "Executive Document Approval"
  }'
```

---

## Client SDK (JS/TS)

A client library is provided in [`sdk/certforge-sdk.js`](file:///e:/projects/certforge/sdk/certforge-sdk.js) and TypeScript types in [`sdk/certforge-sdk.d.ts`](file:///e:/projects/certforge/sdk/certforge-sdk.d.ts).

### JavaScript Example
```javascript
const { CertForgeClient } = require('./sdk/certforge-sdk');

const client = new CertForgeClient('http://127.0.0.1:8443', 'sk_your_api_key_here');

async function run() {
  // 1. Open PIN session
  const tokens = await client.listTokens();
  const session = await client.openSession(tokens.tokens[0].id, '1234');

  // 2. Sign PDF with visible appearance relative to text
  const response = await client.signPdf(session.sessionId, 'rsaKey', pdfBase64, {
    template: 'standard',
    appearance: {
      type: 'text_image',
      searchText: 'Treasury Officer',
      searchPosition: 'above',
      padding: 6,
      textLines: ['Approved electronically', 'Date: {date}'],
      imageBase64: '<BASE64_IMAGE>'
    }
  });

  console.log('Signed PDF ready:', response.document.filename);

  // 3. Close Session
  await client.closeSession(session.sessionId);
}
```

---

## Configuration

### File Location

| Platform | Path |
| --- | --- |
| Windows | `C:\Users\<user>\.certforge\gateway.yml` |
| macOS | `/Users/<user>/.certforge/gateway.yml` |
| Linux | `/home/<user>/.certforge/gateway.yml` |

Override with: `CERTFORGE_CONFIG=/path/to/gateway.yml`

### Environment Variables

| Variable | Description |
| --- | --- |
| `CERTFORGE_CONFIG` | Override config file path |
| `CERTFORGE_PORT` | Override gateway port |
| `CERTFORGE_LIBRARIES` | Extra PKCS#11 library paths (comma-separated) |

---

## Token Support

Supports any PKCS#11-compatible hardware or software token:

| Token | Detection |
| --- | --- |
| SoftHSM2 | Auto-detected at standard installation paths |
| DigiCert USB | Auto-detected if PKCS#11 driver installed |
| YubiKey (PIV) | Auto-detected via OpenSC or YubiKey PKCS#11 |
| SafeNet eToken | Auto-detected via SafeNet client driver |
| OpenSC smart cards | Auto-detected via OpenSC library |
| Custom / Network HSM | Add custom path via `CERTFORGE_LIBRARIES` env var |

---

## Security Model

| Concern | Approach |
| --- | --- |
| Private keys | **Never leave the hardware token** |
| PINs | Held in memory during active session lifetime. Zeroed on close. |
| API access | Bearer API key per request |
| Network | Binds to `127.0.0.1` by default |
| Audit | Append-only JSON log with daily rotation |
| Session expiry | Inactivity timeout + max lifetime enforcement |

---

## Development & Testing

### Build & Run Tests

```bash
./gradlew test build
```

Tests cover:
- JNA discovery and YAML configuration parsing
- Session pool & lifecycle management
- PDFBox 3.x visual appearance stream generation & template placeholder substitution
- Text position finder, multi-page document search, search position offset (`above`/`below`/`left`/`right`/`over`), and boundary clamping
- End-to-end PDF digital signing and verification

---

## License

Apache 2.0 for the gateway core. Proprietary for installers and support.