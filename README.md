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
- [Configuration](#configuration)
- [Token Support](#token-support)
- [Security Model](#security-model)
- [Development](#development)
- [Testing](#testing)
- [License](#license)

---

## Features

- **Zero-config token discovery** — scans known PKCS#11 library paths automatically
- **Session management** — PIN-based sessions with inactivity and max lifetime expiry
- **PDF signing** — PAdES Baseline B using token-backed private keys
- **Signature verification** — document integrity and certificate validation
- **Append-only audit logging** — thread-safe JSON logs with daily rotation
- **API key authentication** — Bearer token on all `/v1/*` endpoints
- **No cloud dependency** — runs entirely locally on localhost
- **Private keys never leave the token**

---

## Architecture

```
┌──────────────────────────────────────────┐
│              Host Machine                  │
│                                            │
│  Business Application ──► localhost:8443   │
│                                  │          │
│                            CertForge        │
│                            Gateway          │
│                            (Service)        │
│                                  │          │
│                          Auto-detect        │
│                          all tokens         │
│                                  │          │
│                    ┌─────────────┴──────┐   │
│                    │                    │   │
│                 USB Token          SoftHSM2 │
│                 (DigiCert)         (dev)    │
└──────────────────────────────────────────┘
```

### Components

| Component | Responsibility |
|-----------|---------------|
| `discovery` | JNA-based PKCS#11 library scanning and token detection |
| `session` | SunPKCS11-based session management with PIN |
| `signing` | PDF signing (PDFBox 3.x + BouncyCastle + PKCS#11) |
| `verify` | Signature verification (CMS + PDF byte range) |
| `audit` | Append-only JSON audit logging |
| `auth` | API key authentication |
| `config` | YAML configuration loading |
| `server` | JDK HttpServer REST API |

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

Produces: `build/libs/certforge-gateway.jar`

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

audit:
  path: "~/.certforge/audit.log"

logging:
  level: "info"
```

### 3. Run

```bash
java --enable-native-access=ALL-UNNAMED -jar build/libs/certforge-gateway.jar
```

### 4. Test

```bash
# Health check (no auth)
curl http://127.0.0.1:8443/health

# List tokens (auth required)
curl -H "Authorization: Bearer sk_your_api_key_here" \
     http://127.0.0.1:8443/v1/tokens
```

---

## API Reference

### Base URL

```
http://127.0.0.1:8443/v1
```

### Authentication Header

```
Authorization: Bearer <api-key>
```

### Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/health` | Health check | No |
| GET | `/v1/tokens` | List detected tokens | Yes |
| POST | `/v1/sessions` | Open session with PIN | Yes |
| GET | `/v1/sessions/{id}/certificates` | List certificates | Yes |
| POST | `/v1/sessions/{id}/jobs` | Sign PDF | Yes |
| DELETE | `/v1/sessions/{id}` | Close session | Yes |
| POST | `/v1/verify` | Verify signed PDF | Yes |

### Open Session

```json
POST /v1/sessions
{
    "tokenId": "slot-249215396",
    "pin": "1234"
}
```

Response:
```json
{
    "sessionId": "a1b2c3d4e5f6..."
}
```

### Sign PDF

```json
POST /v1/sessions/{sessionId}/jobs
{
    "document": "<base64-encoded-pdf>",
    "alias": "myKey"
}
```

Response:
```json
{
    "jobId": "job_abc123",
    "status": "completed",
    "document": {
        "data": "<base64-encoded-signed-pdf>",
        "filename": "signed-document.pdf"
    }
}
```

### Verify PDF

```json
POST /v1/verify
{
    "document": "<base64-encoded-signed-pdf>"
}
```

Response:
```json
{
    "valid": true,
    "signatures": [
        {
            "signer": "CN=My Key, O=Acme Corp",
            "signedAt": "2026-08-13T15:30:15Z",
            "integrity": "intact",
            "certificateValid": true,
            "certificateExpiry": "2027-08-13T00:00:00Z"
        }
    ]
}
```

---

## Configuration

### File Location

| Platform | Path |
|----------|------|
| Windows | `C:\Users\<user>\.certforge\gateway.yml` |
| macOS | `/Users/<user>/.certforge/gateway.yml` |
| Linux | `/home/<user>/.certforge/gateway.yml` |

Override with: `CERTFORGE_CONFIG=/path/to/gateway.yml`

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CERTFORGE_CONFIG` | Override config file path |
| `CERTFORGE_PORT` | Override gateway port |
| `CERTFORGE_LIBRARIES` | Extra PKCS#11 library paths (comma-separated) |

### YAML Interpolation

Config values support `${VARIABLE_NAME}` syntax:

```yaml
gateway:
  apiKeys:
    - "${API_KEY_FROM_ENV}"
```

---

## Token Support

Any PKCS#11-compatible token:

| Token | Detection |
|-------|-----------|
| SoftHSM2 | Auto-detected at standard install paths |
| DigiCert USB | Auto-detected if driver installed |
| YubiKey (PIV) | Auto-detected if driver installed |
| SafeNet eToken | Auto-detected if driver installed |
| OpenSC smart cards | Auto-detected if driver installed |
| Custom/network HSM | Add path via `CERTFORGE_LIBRARIES` env var |

---

## Security Model

| Concern | Approach |
|---------|----------|
| Private keys | Never leave the token |
| PINs | Held in memory only during session lifetime. Zeroed on close. |
| API access | Bearer API key per request |
| Network | Binds to `127.0.0.1` only by default |
| Audit | Append-only JSON log with daily rotation |
| Session expiry | Inactivity timeout + max lifetime |
| Certificate validation | Validity period + key usage + algorithm |

---

## Development

### Build

```bash
./gradlew build
```

### Run Tests

```bash
./gradlew test
```

### Clean Build

```bash
./gradlew clean build
```

### Project Structure

```
src/
├── main/java/com/certforge/
│   ├── GatewayApp.java              (entry point)
│   ├── auth/                        (API key authentication)
│   ├── audit/                       (JSON audit logging)
│   ├── config/                      (YAML config loading)
│   ├── discovery/                   (JNA token discovery)
│   ├── server/                      (REST API server)
│   ├── session/                     (PKCS#11 session management)
│   ├── signing/                     (PDF signing)
│   │   ├── certificate/             (chain validation)
│   │   ├── cms/                     (CMS signature construction)
│   │   ├── crypto/                  (key retrieval + PKCS#11 signer)
│   │   └── exception/               (domain exceptions)
│   └── verify/                      (signature verification)
└── test/java/com/certforge/
    ├── config/
    ├── server/
    ├── session/
    ├── signing/
    └── verify/
```

### Dependencies

| Dependency | Purpose | License |
|-----------|---------|---------|
| JNA | PKCS#11 library discovery | Apache 2.0 |
| SnakeYAML | Configuration parsing | Apache 2.0 |
| PDFBox 3.x | PDF signing | Apache 2.0 |
| BouncyCastle | CMS/PAdES | MIT |
| JUnit 5 | Testing | EPL 2.0 |

---

## Testing

### Unit Tests

```bash
./gradlew test
```

Tests cover:
- Config loading and interpolation
- Session management (expiry, close, nonexistent)
- PDF signing service construction and error handling
- PDF verification service (no signatures, corrupted PDF)
- REST API (auth, health, verification)

### Integration Tests (requires SoftHSM2)

1. Install SoftHSM2
2. Initialize a token:
   ```bash
   softhsm2-util --init-token --slot 0 --label "TestToken" --pin 1234 --so-pin 5678
   ```
3. Run tests — PKCS#11 tests will execute when SoftHSM2 is available

---

## Audit Log

Audit events are written as single-line JSON to the configured path with daily rotation:

```json
{"timestamp":"2026-08-13T15:30:00Z","type":"GATEWAY_STARTED","version":"0.1.0"}
{"timestamp":"2026-08-13T15:30:01Z","type":"TOKEN_DISCOVERY_STARTED","libraries":"6"}
{"timestamp":"2026-08-13T15:30:02Z","type":"TOKEN_FOUND","tokenId":"slot-249215396","label":"SoftHSMToken1","serial":"09af31a70edab9a4"}
{"timestamp":"2026-08-13T15:30:05Z","type":"SESSION_OPENED","sessionId":"abc123","tokenId":"slot-249215396"}
{"timestamp":"2026-08-13T15:30:15Z","type":"DOCUMENT_SIGNED","sessionId":"abc123","alias":"myKey","result":"success","pdfSize":"591620","signatureSize":"8421"}
{"timestamp":"2026-08-13T15:30:20Z","type":"SESSION_CLOSED","sessionId":"abc123","tokenId":"slot-249215396"}
```

---

## License

Apache 2.0 for the gateway core. Proprietary for installers and support.

---

## One-Liner

**CertForge Gateway — plug in your USB token. It auto-detects. Your application signs PDFs via REST API. No cloud. No config. No compromise.**
