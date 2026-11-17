# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

## Cryptographic Design

Invisync uses **AES-256-GCM** (authenticated encryption) for all encryption operations:

| Parameter       | Value                                        |
|-----------------|----------------------------------------------|
| Algorithm       | AES-256-GCM (authenticated encryption + MAC) |
| Key derivation  | PBKDF2-HMAC-SHA256                           |
| KDF iterations  | 600,000 (OWASP 2023 recommendation)          |
| Salt size       | 16 bytes (cryptographically random)          |
| Nonce size      | 12 bytes (cryptographically random)          |
| Wire format     | `salt(16) ‖ nonce(12) ‖ ciphertext+tag`      |

The GCM authentication tag provides integrity verification — any tampering with the ciphertext is detected during decryption.

## Steganography Channels

Each channel embeds data in the **least significant bit (LSB)** of carrier signal samples:

| Channel     | Carrier         | Bits per sample | Notes                                        |
|-------------|-----------------|-----------------|----------------------------------------------|
| Image       | RGB pixels      | 1 per channel   | PNG/BMP only (lossless)                      |
| Audio       | 16-bit PCM      | 1 per sample    | WAV/FLAC/AIFF/MP3 input; WAV output          |
| QR code     | RGB pixels      | 1 per channel   | H-level ECC preserves scannability           |
| Text        | Unicode chars   | —               | Zero-width character insertion               |
| PDF         | Invisible text  | —               | Font-size 0.001pt white text layer           |
| Git         | Commit metadata | 6 bits/commit   | Timestamp % 64 or whitespace encoding        |

**Important**: LSB steganography is NOT secure against a dedicated steganalyst without encryption. Always use the `--password` option when confidentiality is required.

## Security Limitations

- **LSB steganography is detectable** using statistical analysis (chi-square, RS analysis, etc.). Use encryption to protect the payload contents even if the carrier is discovered.
- **MP3 encoding is lossy** — hidden data is embedded in WAV PCM samples; the output must stay in a lossless format. Never re-encode the output to MP3.
- **Git steganography creates evidence** — the commit log contains stego commits. Use with caution on shared repositories.
- **PDF invisible text** can be revealed by selecting-all in a PDF viewer. Use encryption for sensitive payloads.

## Security Controls in the Web API

The web API (`app.py`) implements the following controls:

1. **File size limits** — maximum 50 MB per upload
2. **Magic-byte validation** — file type verified by header bytes, not just extension
3. **Filename sanitization** — allowlist regex strips path traversal characters
4. **Security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
5. **Strict CORS** — configurable origin allowlist
6. **No internal errors exposed** — stack traces are suppressed; clients receive generic messages
7. **Automatic temp-file cleanup** — `TemporaryDirectory` context managers ensure no residual files
8. **Input validation** — all form parameters validated before processing

## Reporting a Vulnerability

If you discover a security vulnerability in Invisync, please **do not** open a public GitHub issue.

Instead, report it privately via GitHub's [Security Advisories](https://github.com/deepmaha2006/steganography-toolkit/security/advisories/new) feature, or email the maintainer directly.

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested mitigation (if any)

You can expect an acknowledgement within **48 hours** and a fix within **7 days** for critical issues.

## Responsible Disclosure

This project follows responsible disclosure principles. Reporters who disclose vulnerabilities privately and allow time for remediation will be credited in the changelog (unless they prefer anonymity).
