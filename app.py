"""
Invisync — Web API  v1
FastAPI backend for the professional steganography toolkit.

Free launch: 10 operations / day / IP address.
API versioning: canonical endpoints are /api/v1/*
                /api/* are backward-compat aliases (same handlers)
When a future v2 is introduced the /api/* and /api/v1/* aliases will start
returning Deprecation headers and eventually 410 — integrators must update.

Security: magic-byte validation, 50 MB upload limit, strict CSP/HSTS,
          no stack traces exposed, CORS, input sanitisation.
"""

import io
import json
import os
import re
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

VERSION         = "1.0.0"
API_VERSION     = 1          # bump to 2 when token-gated endpoints launch
MAX_UPLOAD_BYTES = 50 * 1024 * 1024   # 50 MB

# Free-tier daily limit per IP
DAILY_FREE_LIMIT = 10

# ---------------------------------------------------------------------------
# IP-based rate limiting  (in-memory; resets on cold start)
# ---------------------------------------------------------------------------
# Format: {ip: {"date": "YYYY-MM-DD", "count": int}}
_ip_usage: dict[str, dict] = {}


def _client_ip(request: Request) -> str:
    """Extract real IP — handles Vercel's x-forwarded-for."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return getattr(request.client, "host", "unknown")


def _rate_limit_check(ip: str) -> int:
    """Return remaining ops. Raises 429 if limit reached."""
    today = str(date.today())
    rec = _ip_usage.setdefault(ip, {"date": today, "count": 0})
    if rec["date"] != today:
        rec["date"]  = today
        rec["count"] = 0
    if rec["count"] >= DAILY_FREE_LIMIT:
        reset_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z").replace(
            datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            (date.today().__class__.fromordinal(date.today().toordinal() + 1)).isoformat(),
        )
        raise HTTPException(
            429,
            f"Daily free limit of {DAILY_FREE_LIMIT} operations reached for your IP. "
            "Resets at midnight UTC. The token system is coming soon — "
            "follow https://github.com/deepmaha2006/steganography-toolkit for updates.",
            headers={"Retry-After": "86400", "X-RateLimit-Limit": str(DAILY_FREE_LIMIT)},
        )
    return DAILY_FREE_LIMIT - rec["count"]


def _rate_limit_consume(ip: str) -> int:
    """Deduct one op. Returns remaining count."""
    rec = _ip_usage.get(ip, {"date": str(date.today()), "count": 0})
    rec["count"] += 1
    _ip_usage[ip] = rec
    return max(0, DAILY_FREE_LIMIT - rec["count"])


def _rl_headers(ip: str) -> dict:
    rec   = _ip_usage.get(ip, {"count": 0})
    used  = rec.get("count", 0)
    left  = max(0, DAILY_FREE_LIMIT - used)
    return {
        "X-RateLimit-Limit":     str(DAILY_FREE_LIMIT),
        "X-RateLimit-Remaining": str(left),
        "X-RateLimit-Used":      str(used),
        "X-API-Version":         str(API_VERSION),
    }


# ---------------------------------------------------------------------------
# file type constants
# ---------------------------------------------------------------------------

_ALLOWED_IMAGE_EXT = {".png", ".bmp"}
_ALLOWED_AUDIO_EXT = {".wav", ".flac", ".aiff", ".mp3"}

_MAGIC_PNG     = b"\x89PNG\r\n\x1a\n"
_MAGIC_BMP     = b"BM"
_MAGIC_FLAC    = b"fLaC"
_MAGIC_WAV     = (b"RIFF", b"WAVE")
_MAGIC_PDF     = b"%PDF"
_MAGIC_MP3_ID3 = b"ID3"

_BAD_FILENAME_RE = re.compile(r"[^A-Za-z0-9._\-]")

_static_dir = Path(__file__).parent / "static"


# ---------------------------------------------------------------------------
# middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]   = "nosniff"
        response.headers["X-Frame-Options"]          = "DENY"
        response.headers["X-XSS-Protection"]         = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["X-API-Version"]             = str(API_VERSION)
        response.headers["Content-Security-Policy"]   = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data: blob:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        return response


# ---------------------------------------------------------------------------
# app setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Invisync API",
    description=(
        "Professional steganography toolkit — AES-256-GCM encrypted covert channels.\n\n"
        "**Free launch**: 10 operations / day / IP — no API key required.\n\n"
        "All endpoints are mounted at both `/api/v1/*` (canonical) and `/api/*` (alias). "
        "When the token system launches as v2, `/api/*` aliases will emit `Deprecation` headers. "
        "Integrate against `/api/v1/*` to avoid forced updates."
    ),
    version=VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Used", "X-API-Version"],
    max_age=600,
)

if _static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------

def _safe_filename(filename: str | None) -> str:
    if not filename:
        raise HTTPException(400, "Missing filename")
    name = Path(filename).name
    name = _BAD_FILENAME_RE.sub("_", name)
    if not name or name.startswith("."):
        raise HTTPException(400, "Invalid filename")
    return name


def _check_size(data: bytes, label: str = "File") -> None:
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"{label} exceeds {MAX_UPLOAD_BYTES // 1024 // 1024} MB limit")
    if len(data) == 0:
        raise HTTPException(400, f"{label} is empty")


def _check_image_magic(data: bytes, ext: str) -> None:
    if ext == ".png" and not data.startswith(_MAGIC_PNG):
        raise HTTPException(422, "File does not appear to be a valid PNG")
    if ext == ".bmp" and not data.startswith(_MAGIC_BMP):
        raise HTTPException(422, "File does not appear to be a valid BMP")


def _check_audio_magic(data: bytes, ext: str) -> None:
    if ext == ".flac" and not data.startswith(_MAGIC_FLAC):
        raise HTTPException(422, "File does not appear to be a valid FLAC")
    if ext == ".wav" and not (data[:4] == _MAGIC_WAV[0] and data[8:12] == _MAGIC_WAV[1]):
        raise HTTPException(422, "File does not appear to be a valid WAV")
    if ext == ".mp3" and not (
        data.startswith(_MAGIC_MP3_ID3)
        or (data[0:1] == b"\xff" and data[1:2] in {b"\xfb", b"\xf3", b"\xf2", b"\xe3"})
    ):
        raise HTTPException(422, "File does not appear to be a valid MP3")


def _check_pdf_magic(data: bytes) -> None:
    if not data.startswith(_MAGIC_PDF):
        raise HTTPException(422, "File does not appear to be a valid PDF")


async def _read_upload(upload: UploadFile, label: str = "File") -> tuple[bytes, str]:
    name = _safe_filename(upload.filename)
    ext  = Path(name).suffix.lower()
    data = await upload.read()
    _check_size(data, label)
    return data, ext


# ---------------------------------------------------------------------------
# health & pages
# ---------------------------------------------------------------------------

@app.get("/api/health")
@app.get("/api/v1/health")
async def health(request: Request):
    ip  = _client_ip(request)
    rec = _ip_usage.get(ip, {"date": str(date.today()), "count": 0})
    return {
        "status":   "ok",
        "version":  VERSION,
        "api_version": API_VERSION,
        "service":  "Invisync",
        "daily_limit":    DAILY_FREE_LIMIT,
        "daily_used":     rec.get("count", 0),
        "daily_remaining": max(0, DAILY_FREE_LIMIT - rec.get("count", 0)),
    }


@app.get("/", response_class=HTMLResponse)
async def root():
    index = _static_dir / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Invisync</h1><p><a href='/api/docs'>API Docs</a></p>")


@app.get("/developer", response_class=HTMLResponse)
async def developer_page():
    page = _static_dir / "developer.html"
    if page.exists():
        return HTMLResponse(page.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Developer</h1>")


# ---------------------------------------------------------------------------
# image — /api/image/* and /api/v1/image/* (same handlers)
# ---------------------------------------------------------------------------

@app.post("/api/image/encode")
@app.post("/api/v1/image/encode")
async def image_encode(
    request: Request,
    cover:    UploadFile     = File(..., description="Cover image (PNG or BMP)"),
    message:  Optional[str]  = Form(None),
    password: Optional[str]  = Form(None),
):
    ip = _client_ip(request)
    _rate_limit_check(ip)

    cover_data, cover_ext = await _read_upload(cover, "Cover image")
    if cover_ext not in _ALLOWED_IMAGE_EXT:
        raise HTTPException(422, f"Cover must be PNG or BMP, got '{cover_ext}'")
    _check_image_magic(cover_data, cover_ext)
    if not message:
        raise HTTPException(400, "message is required")

    payload = message.encode("utf-8")
    if password:
        from stego.crypto import encrypt
        payload = encrypt(payload, password)

    with tempfile.TemporaryDirectory() as tmp:
        cover_path = Path(tmp) / f"cover{cover_ext}"
        out_path   = Path(tmp) / f"stego{cover_ext}"
        cover_path.write_bytes(cover_data)
        try:
            from stego import image_stego
            image_stego.encode(cover_path, payload, out_path)
        except ValueError as e:
            raise HTTPException(422, str(e))

        rem = _rate_limit_consume(ip)
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="image/png" if cover_ext == ".png" else "image/bmp",
            headers={
                "Content-Disposition": f"attachment; filename=stego{cover_ext}",
                **_rl_headers(ip),
            },
        )


@app.post("/api/image/decode")
@app.post("/api/v1/image/decode")
async def image_decode(
    request:  Request,
    stego:    UploadFile     = File(..., description="Stego image (PNG or BMP)"),
    password: Optional[str]  = Form(None),
):
    ip = _client_ip(request)
    _rate_limit_check(ip)

    stego_data, stego_ext = await _read_upload(stego, "Stego image")
    if stego_ext not in _ALLOWED_IMAGE_EXT:
        raise HTTPException(422, f"Image must be PNG or BMP, got '{stego_ext}'")
    _check_image_magic(stego_data, stego_ext)

    with tempfile.TemporaryDirectory() as tmp:
        stego_path = Path(tmp) / f"stego{stego_ext}"
        stego_path.write_bytes(stego_data)
        try:
            from stego import image_stego
            payload = image_stego.decode(stego_path)
        except ValueError as e:
            raise HTTPException(422, str(e))

    if password:
        try:
            from stego.crypto import decrypt
            payload = decrypt(payload, password)
        except ValueError:
            raise HTTPException(422, "Decryption failed — wrong password or corrupt data")

    _rate_limit_consume(ip)
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_rl_headers(ip))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_rl_headers(ip))


# ---------------------------------------------------------------------------
# audio — /api/audio/* and /api/v1/audio/*
# ---------------------------------------------------------------------------

@app.post("/api/audio/encode")
@app.post("/api/v1/audio/encode")
async def audio_encode(
    request:  Request,
    cover:    UploadFile     = File(..., description="Cover audio (WAV, FLAC, AIFF, or MP3)"),
    message:  Optional[str]  = Form(None),
    password: Optional[str]  = Form(None),
):
    ip = _client_ip(request)
    _rate_limit_check(ip)

    cover_data, cover_ext = await _read_upload(cover, "Cover audio")
    if cover_ext not in _ALLOWED_AUDIO_EXT:
        raise HTTPException(422, f"Audio must be WAV/FLAC/AIFF/MP3, got '{cover_ext}'")
    _check_audio_magic(cover_data, cover_ext)
    if not message:
        raise HTTPException(400, "message is required")

    payload = message.encode("utf-8")
    if password:
        from stego.crypto import encrypt
        payload = encrypt(payload, password)

    with tempfile.TemporaryDirectory() as tmp:
        cover_path = Path(tmp) / f"cover{cover_ext}"
        out_path   = Path(tmp) / "stego.wav"
        cover_path.write_bytes(cover_data)
        try:
            from stego import audio_stego
            audio_stego.encode(cover_path, payload, out_path)
        except ValueError as e:
            raise HTTPException(422, str(e))
        except ImportError as e:
            raise HTTPException(503, str(e))

        _rate_limit_consume(ip)
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="audio/wav",
            headers={"Content-Disposition": "attachment; filename=stego.wav", **_rl_headers(ip)},
        )


@app.post("/api/audio/decode")
@app.post("/api/v1/audio/decode")
async def audio_decode(
    request:  Request,
    stego:    UploadFile     = File(..., description="Stego audio (WAV, FLAC, or AIFF)"),
    password: Optional[str]  = Form(None),
):
    ip = _client_ip(request)
    _rate_limit_check(ip)

    stego_data, stego_ext = await _read_upload(stego, "Stego audio")
    if stego_ext not in _ALLOWED_AUDIO_EXT:
        raise HTTPException(422, f"Audio must be WAV/FLAC/AIFF/MP3, got '{stego_ext}'")
    _check_audio_magic(stego_data, stego_ext)

    with tempfile.TemporaryDirectory() as tmp:
        stego_path = Path(tmp) / f"stego{stego_ext}"
        stego_path.write_bytes(stego_data)
        try:
            from stego import audio_stego
            payload = audio_stego.decode(stego_path)
        except ValueError as e:
            raise HTTPException(422, str(e))

    if password:
        try:
            from stego.crypto import decrypt
            payload = decrypt(payload, password)
        except ValueError:
            raise HTTPException(422, "Decryption failed — wrong password or corrupt data")

    _rate_limit_consume(ip)
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_rl_headers(ip))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_rl_headers(ip))


# ---------------------------------------------------------------------------
# text — /api/text/* and /api/v1/text/*
# ---------------------------------------------------------------------------

@app.post("/api/text/encode")
@app.post("/api/v1/text/encode")
async def text_encode(
    request:  Request,
    cover:    str            = Form(..., description="Visible cover text"),
    message:  str            = Form(..., description="Secret message to hide"),
    password: Optional[str]  = Form(None),
):
    ip = _client_ip(request)
    _rate_limit_check(ip)

    if not cover.strip():
        raise HTTPException(400, "cover text cannot be empty")
    if not message.strip():
        raise HTTPException(400, "message cannot be empty")

    payload = message.encode("utf-8")
    if password:
        from stego.crypto import encrypt
        payload = encrypt(payload, password)

    from stego import text_stego
    stego_text = text_stego.encode(cover, payload)
    _rate_limit_consume(ip)
    return JSONResponse({"stego_text": stego_text, "size_bytes": len(payload)},
                        headers=_rl_headers(ip))


@app.post("/api/text/decode")
@app.post("/api/v1/text/decode")
async def text_decode(
    request:    Request,
    stego_text: str           = Form(..., description="Text containing hidden payload"),
    password:   Optional[str] = Form(None),
):
    ip = _client_ip(request)
    _rate_limit_check(ip)

    if not stego_text:
        raise HTTPException(400, "stego_text cannot be empty")

    try:
        from stego import text_stego
        payload = text_stego.decode(stego_text)
    except ValueError as e:
        raise HTTPException(422, str(e))

    if password:
        try:
            from stego.crypto import decrypt
            payload = decrypt(payload, password)
        except ValueError:
            raise HTTPException(422, "Decryption failed — wrong password or corrupt data")

    _rate_limit_consume(ip)
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_rl_headers(ip))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_rl_headers(ip))


# ---------------------------------------------------------------------------
# PDF — /api/pdf/* and /api/v1/pdf/*
# ---------------------------------------------------------------------------

@app.post("/api/pdf/encode")
@app.post("/api/v1/pdf/encode")
async def pdf_encode(
    request:      Request,
    message:      str                 = Form(...),
    password:     Optional[str]       = Form(None),
    visible_text: str                 = Form("Report"),
    cover:        Optional[UploadFile] = File(None, description="Existing PDF (optional)"),
):
    ip = _client_ip(request)
    _rate_limit_check(ip)

    if not message.strip():
        raise HTTPException(400, "message cannot be empty")

    payload = message.encode("utf-8")
    if password:
        from stego.crypto import encrypt
        payload = encrypt(payload, password)

    with tempfile.TemporaryDirectory() as tmp:
        out_path       = Path(tmp) / "stego.pdf"
        input_pdf_path = None

        if cover is not None:
            cover_data, cover_ext = await _read_upload(cover, "Cover PDF")
            if cover_ext != ".pdf":
                raise HTTPException(422, "Cover must be a PDF")
            _check_pdf_magic(cover_data)
            input_pdf_path = Path(tmp) / "cover.pdf"
            input_pdf_path.write_bytes(cover_data)

        try:
            from stego import pdf_stego
            pdf_stego.encode(payload, out_path, input_pdf=input_pdf_path, visible_text=visible_text)
        except Exception as e:
            raise HTTPException(422, str(e))

        _rate_limit_consume(ip)
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=stego.pdf", **_rl_headers(ip)},
        )


@app.post("/api/pdf/decode")
@app.post("/api/v1/pdf/decode")
async def pdf_decode(
    request:  Request,
    stego:    UploadFile     = File(..., description="Stego PDF"),
    password: Optional[str]  = Form(None),
):
    ip = _client_ip(request)
    _rate_limit_check(ip)

    stego_data, stego_ext = await _read_upload(stego, "Stego PDF")
    if stego_ext != ".pdf":
        raise HTTPException(422, "File must be a PDF")
    _check_pdf_magic(stego_data)

    with tempfile.TemporaryDirectory() as tmp:
        stego_path = Path(tmp) / "stego.pdf"
        stego_path.write_bytes(stego_data)
        try:
            from stego import pdf_stego
            payload = pdf_stego.decode(stego_path)
        except ValueError as e:
            raise HTTPException(422, str(e))

    if password:
        try:
            from stego.crypto import decrypt
            payload = decrypt(payload, password)
        except ValueError:
            raise HTTPException(422, "Decryption failed — wrong password or corrupt data")

    _rate_limit_consume(ip)
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_rl_headers(ip))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_rl_headers(ip))


# ---------------------------------------------------------------------------
# QR — /api/qr/* and /api/v1/qr/*
# ---------------------------------------------------------------------------

@app.post("/api/qr/generate")
@app.post("/api/v1/qr/generate")
async def qr_generate(
    request: Request,
    url:     str = Form(..., description="URL to encode in QR"),
    scale:   int = Form(10),
):
    ip = _client_ip(request)
    _rate_limit_check(ip)

    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    if not 1 <= scale <= 20:
        raise HTTPException(400, "scale must be between 1 and 20")

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "qr.png"
        from stego import qr_stego
        qr_stego.generate_qr(url, out_path, scale)
        _rate_limit_consume(ip)
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="image/png",
            headers={"Content-Disposition": "attachment; filename=qr.png", **_rl_headers(ip)},
        )


@app.post("/api/qr/encode")
@app.post("/api/v1/qr/encode")
async def qr_encode(
    request:  Request,
    url:      str            = Form(..., description="URL to encode in QR (stays scannable)"),
    message:  str            = Form(..., description="Secret message to hide inside the QR image"),
    scale:    int            = Form(10),
    password: Optional[str]  = Form(None),
):
    """Generate a scannable QR code for *url* and embed *message* in its pixel LSBs."""
    ip = _client_ip(request)
    _rate_limit_check(ip)

    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    if not 1 <= scale <= 20:
        raise HTTPException(400, "scale must be between 1 and 20")
    if not message.strip():
        raise HTTPException(400, "message cannot be empty")

    payload = message.encode("utf-8")
    if password:
        from stego.crypto import encrypt
        payload = encrypt(payload, password)

    with tempfile.TemporaryDirectory() as tmp:
        qr_path  = Path(tmp) / "qr.png"
        out_path = Path(tmp) / "stego_qr.png"
        from stego import qr_stego
        qr_stego.generate_qr(url, qr_path, scale)
        try:
            qr_stego.encode(qr_path, payload, out_path)
        except ValueError as e:
            raise HTTPException(422, str(e))

        _rate_limit_consume(ip)
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="image/png",
            headers={"Content-Disposition": "attachment; filename=stego_qr.png", **_rl_headers(ip)},
        )


@app.post("/api/qr/decode")
@app.post("/api/v1/qr/decode")
async def qr_decode(
    request:  Request,
    stego:    UploadFile     = File(..., description="Stego QR image (PNG)"),
    password: Optional[str]  = Form(None),
):
    """Extract the hidden message from a stego QR image."""
    ip = _client_ip(request)
    _rate_limit_check(ip)

    stego_data, stego_ext = await _read_upload(stego, "Stego QR image")
    if stego_ext != ".png":
        raise HTTPException(422, "QR stego image must be PNG")
    _check_image_magic(stego_data, ".png")

    with tempfile.TemporaryDirectory() as tmp:
        stego_path = Path(tmp) / "stego_qr.png"
        stego_path.write_bytes(stego_data)
        try:
            from stego import qr_stego
            payload = qr_stego.decode(stego_path)
        except ValueError as e:
            raise HTTPException(422, str(e))

    if password:
        try:
            from stego.crypto import decrypt
            payload = decrypt(payload, password)
        except ValueError:
            raise HTTPException(422, "Decryption failed — wrong password or corrupt data")

    _rate_limit_consume(ip)
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_rl_headers(ip))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_rl_headers(ip))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
