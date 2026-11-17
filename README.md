# Invisync

> **Professional-grade steganography toolkit** — hide AES-256-GCM encrypted data inside images, audio (WAV/FLAC/MP3), QR codes, text, PDF, and git commits.

[![CI](https://github.com/deepmaha2006/steganography-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/deepmaha2006/steganography-toolkit/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: AES-256-GCM](https://img.shields.io/badge/Encryption-AES--256--GCM-green.svg)](SECURITY.md)

---

## Overview

Invisync embeds arbitrary payloads into carrier files using **Least Significant Bit (LSB) steganography**, with optional **AES-256-GCM authenticated encryption**. It ships as both a **CLI tool** and a **FastAPI web application**.

```
┌─────────────────────────────────────────────────────────────┐
│                        INVISYNC                             │
│          Professional Steganography Toolkit                 │
├──────────┬──────────┬──────────┬────────┬──────┬──────────┤
│  Image   │  Audio   │  QR Code │  Text  │  PDF │   Git    │
│ PNG·BMP  │ WAV·MP3  │   PNG    │Unicode │      │ Commits  │
│          │ FLAC·AIFF│          │        │      │          │
├──────────┴──────────┴──────────┴────────┴──────┴──────────┤
│               AES-256-GCM  ·  PBKDF2-HMAC-SHA256           │
│               600,000 iterations  ·  16-byte salt           │
└─────────────────────────────────────────────────────────────┘
```

---

## Features

| Channel    | Carrier Formats              | Technique                        | Capacity              |
|------------|------------------------------|----------------------------------|-----------------------|
| **Image**  | PNG, BMP                     | LSB (1 bit per RGB channel)      | ~37 KB per MP                |
| **Audio**  | WAV, FLAC, AIFF, **MP3**     | LSB (1 bit per 16-bit PCM sample)| ~330 KB per 30s stereo WAV   |
| **QR Code**| PNG                          | LSB in QR pixel data (ECC H)     | Varies by QR scale           |
| **Text**   | Any Unicode text             | Zero-width character insertion   | Unlimited                    |
| **PDF**    | PDF                          | Invisible text layer / metadata  | Unlimited                    |
| **Git**    | Any git repository           | Timestamp % 64 / whitespace      | Unlimited (commits)          |

**Encryption:** AES-256-GCM with PBKDF2-HMAC-SHA256 (600 000 iterations, OWASP 2023).

---

## Security Architecture

```
Password ──► PBKDF2-HMAC-SHA256 (600,000 iters) ──► 256-bit key
                                                          │
                                                     AES-256-GCM
                                                          │
                                              Authenticated ciphertext
                                            (integrity protected by GCM tag)
                                                          │
                                                   LSB embedding
                                                     in carrier
```

See [SECURITY.md](SECURITY.md) for the full threat model, cryptographic parameters, and responsible disclosure policy.

---

## Installation

### Prerequisites

- Python 3.10 or later
- `ffmpeg` — required for MP3 support (audio steganography)

```bash
# Ubuntu / Debian
sudo apt-get install ffmpeg libsndfile1

# macOS (Homebrew)
brew install ffmpeg

# Windows (winget)
winget install ffmpeg
```

### Install from source

```bash
git clone https://github.com/deepmaha2006/steganography-toolkit.git
cd steganography-toolkit
pip install -r requirements.txt
```

### Install as a package (CLI entry point)

```bash
pip install .
# exposes the `invisync` command
```

---

## CLI Usage

The CLI is available as `python -m stego` (from source) or `invisync` (after package install).

### Image Steganography

```bash
# Encode a message into a PNG
python -m stego image encode \
  --input  photo.png \
  --message "Operation Nightfall begins at dawn" \
  --output  stego.png

# Encode + AES-256-GCM encryption
python -m stego image encode \
  --input    photo.png \
  --file     secret.bin \
  --password "s3cur3P@ssw0rd!" \
  --output   stego_enc.png

# Decode
python -m stego image decode --input stego_enc.png --password "s3cur3P@ssw0rd!"
```

### Audio Steganography (WAV / FLAC / AIFF / MP3)

```bash
# Encode into WAV
python -m stego audio encode \
  --input  recording.wav \
  --message "coordinates: 51.5074 N, 0.1278 W" \
  --output  stego.wav

# Encode MP3 input → WAV output (lossy MP3 re-encoding would destroy hidden bits)
python -m stego audio encode \
  --input  track.mp3 \
  --message "rendezvous at 0300" \
  --output  stego.wav

# Decode
python -m stego audio decode --input stego.wav
```

> **Note:** MP3 is accepted as *input* only. Output is always a lossless format (WAV/FLAC/AIFF) because MP3 compression destroys LSB data.

### QR Code Steganography

```bash
# Generate a QR code
python -m stego qr generate --url https://example.com --output qr.png

# Encode a secret into the QR PNG (QR remains scannable — ECC H level)
python -m stego qr encode --input qr.png --message "hidden payload" --output stego_qr.png

# Decode
python -m stego qr decode --input stego_qr.png
```

### Text Steganography (Zero-Width Unicode)

```bash
# Encode: embeds secret using U+200B/U+200C/U+200D invisible chars
python -m stego text encode \
  --cover  "Hello, this is an ordinary email." \
  --message "Package dropped at dead drop alpha" \
  --output  stego.txt

# Decode
python -m stego text decode --input stego.txt
```

### PDF Steganography

```bash
# New PDF with invisible text layer
python -m stego pdf encode --message "embedded data" --output stego.pdf

# Inject into existing PDF via /Keywords metadata
python -m stego pdf encode \
  --input   existing.pdf \
  --message "metadata payload" \
  --output  stego_meta.pdf

# Decode
python -m stego pdf decode --input stego.pdf
```

### Git Commit Steganography

```bash
# Timestamp channel (seconds % 64 → 6 bits/commit)
python -m stego git encode \
  --repo    /path/to/repo \
  --message "covert message" \
  --channel timestamp

# Whitespace channel (commit message body)
python -m stego git encode \
  --repo    /path/to/repo \
  --message "covert message" \
  --channel whitespace

# Decode
python -m stego git decode --repo /path/to/repo --channel timestamp
```

### Capacity Report

```bash
python -m stego capacity --input photo.png
# → Image capacity : 22,491 bytes (22.0 KB)

python -m stego capacity --input recording.mp3
# → Audio capacity : 330,562 bytes (322.8 KB)
```

---

## Web Interface

**Live demo → [https://invisync.vercel.app](https://invisync.vercel.app)**

Invisync also ships a FastAPI web application with a clean browser UI.

```bash
# Install web dependencies
pip install ".[web]"

# Start the server
python app.py
# → http://localhost:8000
```

Navigate to `http://localhost:8000` for the drag-and-drop web interface.  
API documentation is available at `http://localhost:8000/api/docs`.

### API Endpoints

| Method | Endpoint            | Description                       |
|--------|---------------------|-----------------------------------|
| GET    | `/api/health`       | Health check                      |
| POST   | `/api/image/encode` | Encode message into PNG/BMP       |
| POST   | `/api/image/decode` | Decode message from PNG/BMP       |
| POST   | `/api/audio/encode` | Encode into WAV/FLAC/AIFF/MP3     |
| POST   | `/api/audio/decode` | Decode from audio file            |
| POST   | `/api/text/encode`  | Zero-width Unicode encode         |
| POST   | `/api/text/decode`  | Zero-width Unicode decode         |
| POST   | `/api/pdf/encode`   | Encode into PDF                   |
| POST   | `/api/pdf/decode`   | Decode from PDF                   |
| POST   | `/api/qr/generate`  | Generate QR code PNG              |

---

## Project Structure

```
invisync/
├── stego/                  # Core library
│   ├── __init__.py
│   ├── crypto.py           # AES-256-GCM encryption layer
│   ├── image_stego.py      # PNG/BMP LSB steganography
│   ├── audio_stego.py      # WAV/FLAC/AIFF/MP3 LSB steganography
│   ├── qr_stego.py         # QR code LSB steganography
│   ├── text_stego.py       # Zero-width Unicode steganography
│   ├── pdf_stego.py        # PDF invisible-text / metadata
│   ├── git_stego.py        # Git commit metadata steganography
│   └── cli.py              # Click CLI entry point
├── static/
│   └── index.html          # Web UI
├── app.py                  # FastAPI web application
├── test_all.py             # End-to-end test suite
├── pyproject.toml
├── requirements.txt
├── vercel.json             # Vercel deployment config
├── SECURITY.md
└── LICENSE
```

---

## Running Tests

```bash
python test_all.py
```

All 7 test suites (crypto, image, audio, QR, text, PDF, git) must pass before any release.

---

## Security Checklist

The following security measures are implemented or verified:

- [x] **AES-256-GCM** authenticated encryption — provides confidentiality + integrity
- [x] **PBKDF2-HMAC-SHA256** key derivation with 600,000 iterations (OWASP 2023)
- [x] **Cryptographically random** salt (16 bytes) and nonce (12 bytes) per encryption
- [x] **Magic-byte validation** — file types verified by header, not just extension
- [x] **File size limits** — 100 MB CLI, 50 MB web API
- [x] **Path traversal protection** — filenames sanitized via allowlist regex
- [x] **Security HTTP headers** — HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy
- [x] **No internal errors exposed** — stack traces suppressed in API responses
- [x] **Temp file auto-cleanup** — `TemporaryDirectory` context managers
- [x] **Input validation** — all parameters validated before processing
- [x] **Lossless-only output warning** — prevents accidental MP3 re-encoding
- [x] **Dependency versions pinned** — minimum versions with no known CVEs
- [x] **CI security scan** — `bandit` (SAST) + `pip-audit` (SCA) on every push

---

## Contributing

This repository is maintained solely by **[deepmaha2006](https://github.com/deepmaha2006)**.  
Issues and pull requests are welcome — please review the security policy before reporting vulnerabilities.  
No other contributors are authorised to merge changes.

---

## License

[MIT](LICENSE) © 2026 deepmaha2006
