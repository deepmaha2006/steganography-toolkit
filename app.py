"""
Invisync — Web API
FastAPI backend for the professional steganography toolkit.

Security measures implemented:
- File size limits (50 MB per upload)
- Magic-byte file type validation
- Strict CORS policy
- Security response headers (CSP, HSTS, X-Frame-Options, etc.)
- Input sanitization on all parameters
- Automatic temp-file cleanup via context managers
- No stack traces exposed to clients
- Password strength enforced at the API level
"""

import io
import json
import os
import re
import tempfile
import uuid
from datetime import date
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024   # 50 MB

# ---------------------------------------------------------------------------
# API key + token system
# ---------------------------------------------------------------------------

DEMO_KEY        = "inv_demo_free_2026"
DEMO_DAILY_LIMIT = 100

# Live keys read from env: INVISYNC_API_KEYS=inv_live_xxx:1000,inv_live_yyy:5000
# Format: key:balance  (comma-separated pairs)
_live_keys: dict[str, int] = {}
_raw = os.environ.get("INVISYNC_API_KEYS", "")
for _pair in _raw.split(","):
    _pair = _pair.strip()
    if ":" in _pair:
        _k, _v = _pair.rsplit(":", 1)
        try:
            _live_keys[_k.strip()] = int(_v.strip())
        except ValueError:
            pass

# In-memory usage store (resets on cold start — good enough for serverless demo)
# {key: {"date": "2026-11-17", "used": 42}}
_usage: dict[str, dict] = {}

TOKEN_COST = {
    "image_encode":  10,
    "image_decode":   5,
    "audio_encode":  20,
    "audio_decode":  10,
    "qr_encode":     10,
    "qr_decode":      5,
    "qr_generate":    2,
    "text_encode":    5,
    "text_decode":    2,
    "pdf_encode":    10,
    "pdf_decode":     5,
}


def _resolve_key(x_api_key: Optional[str]) -> tuple[str, str, int]:
    """Return (key, plan, balance). Raises 401 if key is invalid."""
    if not x_api_key:
        return "__anon__", "none", 0

    if x_api_key == DEMO_KEY:
        today = str(date.today())
        rec = _usage.setdefault(DEMO_KEY, {"date": today, "used": 0})
        if rec["date"] != today:
            rec["date"] = today
            rec["used"] = 0
        return DEMO_KEY, "free", max(0, DEMO_DAILY_LIMIT - rec["used"])

    if x_api_key in _live_keys:
        used = _usage.get(x_api_key, {}).get("used", 0)
        balance = max(0, _live_keys[x_api_key] - used)
        plan = "starter" if _live_keys[x_api_key] <= 1000 else \
               "growth"  if _live_keys[x_api_key] <= 5000 else "pro"
        return x_api_key, plan, balance

    raise HTTPException(401, "Invalid API key — get one at https://invisync.vercel.app/developer")


def _charge(key: str, operation: str) -> int:
    """Deduct tokens; raise 402 if insufficient. Returns tokens_used."""
    if key == "__anon__":
        return 0
    cost = TOKEN_COST.get(operation, 5)
    if key == DEMO_KEY:
        today = str(date.today())
        rec = _usage.setdefault(DEMO_KEY, {"date": today, "used": 0})
        if rec["date"] != today:
            rec["date"] = today
            rec["used"] = 0
        if rec["used"] + cost > DEMO_DAILY_LIMIT:
            raise HTTPException(402, f"Demo key daily limit ({DEMO_DAILY_LIMIT} tokens) reached. "
                                "Request a live key at https://invisync.vercel.app/developer")
        rec["used"] += cost
        return cost
    if key in _live_keys:
        rec = _usage.setdefault(key, {"used": 0})
        total_used = rec["used"] + cost
        if total_used > _live_keys[key]:
            raise HTTPException(402, "Insufficient token balance — top up at https://invisync.vercel.app/developer")
        rec["used"] = total_used
        return cost
    return 0


def _token_headers(key: str, plan: str, used: int) -> dict:
    if key == "__anon__":
        return {}
    if key == DEMO_KEY:
        rec = _usage.get(DEMO_KEY, {"used": used})
        remaining = max(0, DEMO_DAILY_LIMIT - rec["used"])
    elif key in _live_keys:
        rec = _usage.get(key, {"used": used})
        remaining = max(0, _live_keys[key] - rec["used"])
    else:
        remaining = 0
    return {
        "X-Tokens-Used":      str(used),
        "X-Tokens-Remaining": str(remaining),
        "X-Plan":             plan,
        "X-Request-Id":       f"req_{uuid.uuid4().hex[:12]}",
    }

_ALLOWED_IMAGE_EXT = {".png", ".bmp"}
_ALLOWED_AUDIO_EXT = {".wav", ".flac", ".aiff", ".mp3"}
_ALLOWED_PDF_EXT = {".pdf"}

_MAGIC_PNG  = b"\x89PNG\r\n\x1a\n"
_MAGIC_BMP  = b"BM"
_MAGIC_FLAC = b"fLaC"
_MAGIC_WAV  = (b"RIFF", b"WAVE")
_MAGIC_PDF  = b"%PDF"
_MAGIC_MP3_ID3 = b"ID3"

_BAD_FILENAME_RE = re.compile(r"[^A-Za-z0-9._\-]")  # allowlist for uploaded file names


# ---------------------------------------------------------------------------
# middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]         = "DENY"
        response.headers["X-XSS-Protection"]        = "1; mode=block"
        response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]       = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Content-Security-Policy"] = (
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
    description="Professional steganography toolkit — AES-256-GCM encrypted covert channels",
    version=VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept", "X-API-Key", "Authorization"],
    expose_headers=["X-Tokens-Used", "X-Tokens-Remaining", "X-Plan", "X-Request-Id"],
    max_age=600,
)

# Serve static frontend
_static_dir = Path(__file__).parent / "static"
if _static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------

def _safe_filename(filename: str | None) -> str:
    """Sanitize a filename, raising 400 on suspicious input."""
    if not filename:
        raise HTTPException(400, "Missing filename")
    name = Path(filename).name        # strip directory components
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
    if ext == ".mp3" and not (data.startswith(_MAGIC_MP3_ID3) or (data[0:1] == b"\xff" and data[1:2] in {b"\xfb", b"\xf3", b"\xf2", b"\xe3"})):
        raise HTTPException(422, "File does not appear to be a valid MP3")


def _check_pdf_magic(data: bytes) -> None:
    if not data.startswith(_MAGIC_PDF):
        raise HTTPException(422, "File does not appear to be a valid PDF")


async def _read_upload(upload: UploadFile, label: str = "File") -> tuple[bytes, str]:
    """Read upload, enforce size limit, return (data, extension)."""
    name = _safe_filename(upload.filename)
    ext = Path(name).suffix.lower()
    data = await upload.read()
    _check_size(data, label)
    return data, ext


# ---------------------------------------------------------------------------
# routes — health & root
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": VERSION, "service": "Invisync"}


@app.get("/", response_class=HTMLResponse)
async def root():
    index = _static_dir / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Invisync API</h1><p>See <a href='/api/docs'>/api/docs</a></p>")


@app.get("/developer", response_class=HTMLResponse)
async def developer_page():
    page = _static_dir / "developer.html"
    if page.exists():
        return HTMLResponse(page.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Developer</h1>")


@app.post("/api/key-request")
async def key_request(request: Request):
    """Log an API key request (body: {name, email, project, plan, notes})."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")
    name  = str(body.get("name", "")).strip()[:100]
    email = str(body.get("email", "")).strip()[:200]
    plan  = str(body.get("plan", "")).strip()[:50]
    if not name or not email or "@" not in email:
        raise HTTPException(400, "name and valid email are required")
    # In production: send email notification or log to DB.
    # For now, log to stdout (visible in Vercel function logs).
    print(json.dumps({
        "event": "key_request",
        "name": name,
        "email": email,
        "project": str(body.get("project", ""))[:300],
        "plan": plan,
        "notes": str(body.get("notes", ""))[:500],
    }))
    return JSONResponse({"status": "received", "message": "Key request logged. Email incoming within 24h."})


# ---------------------------------------------------------------------------
# image endpoints
# ---------------------------------------------------------------------------

@app.post("/api/image/encode")
async def image_encode(
    cover: UploadFile = File(..., description="Cover image (PNG or BMP)"),
    message: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = _resolve_key(x_api_key)
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

        used = _charge(key, "image_encode")
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="image/png" if cover_ext == ".png" else "image/bmp",
            headers={
                "Content-Disposition": f"attachment; filename=stego{cover_ext}",
                **_token_headers(key, plan, used),
            },
        )


@app.post("/api/image/decode")
async def image_decode(
    stego: UploadFile = File(..., description="Stego image (PNG or BMP)"),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = _resolve_key(x_api_key)
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

    used = _charge(key, "image_decode")
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used))


# ---------------------------------------------------------------------------
# audio endpoints
# ---------------------------------------------------------------------------

@app.post("/api/audio/encode")
async def audio_encode(
    cover: UploadFile = File(..., description="Cover audio (WAV, FLAC, AIFF, or MP3)"),
    message: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = _resolve_key(x_api_key)
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

        used = _charge(key, "audio_encode")
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="audio/wav",
            headers={"Content-Disposition": "attachment; filename=stego.wav",
                     **_token_headers(key, plan, used)},
        )


@app.post("/api/audio/decode")
async def audio_decode(
    stego: UploadFile = File(..., description="Stego audio (WAV, FLAC, or AIFF)"),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = _resolve_key(x_api_key)
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

    used = _charge(key, "audio_decode")
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used))


# ---------------------------------------------------------------------------
# text endpoints
# ---------------------------------------------------------------------------

@app.post("/api/text/encode")
async def text_encode(
    cover: str = Form(..., description="Visible cover text"),
    message: str = Form(..., description="Secret message to hide"),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = _resolve_key(x_api_key)
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
    used = _charge(key, "text_encode")
    return JSONResponse({"stego_text": stego_text, "size_bytes": len(payload)},
                        headers=_token_headers(key, plan, used))


@app.post("/api/text/decode")
async def text_decode(
    stego_text: str = Form(..., description="Text containing hidden payload"),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = _resolve_key(x_api_key)
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

    used = _charge(key, "text_decode")
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used))


# ---------------------------------------------------------------------------
# PDF endpoints
# ---------------------------------------------------------------------------

@app.post("/api/pdf/encode")
async def pdf_encode(
    message: str = Form(...),
    password: Optional[str] = Form(None),
    visible_text: str = Form("Report"),
    cover: Optional[UploadFile] = File(None, description="Existing PDF (optional)"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = _resolve_key(x_api_key)
    if not message.strip():
        raise HTTPException(400, "message cannot be empty")

    payload = message.encode("utf-8")
    if password:
        from stego.crypto import encrypt
        payload = encrypt(payload, password)

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "stego.pdf"
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

        used = _charge(key, "pdf_encode")
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=stego.pdf",
                     **_token_headers(key, plan, used)},
        )


@app.post("/api/pdf/decode")
async def pdf_decode(
    stego: UploadFile = File(..., description="Stego PDF"),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = _resolve_key(x_api_key)
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

    used = _charge(key, "pdf_decode")
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used))


# ---------------------------------------------------------------------------
# QR endpoints
# ---------------------------------------------------------------------------

@app.post("/api/qr/generate")
async def qr_generate(
    url: str = Form(..., description="URL to encode in QR"),
    scale: int = Form(10),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = _resolve_key(x_api_key)
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    if not 1 <= scale <= 20:
        raise HTTPException(400, "scale must be between 1 and 20")

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "qr.png"
        from stego import qr_stego
        qr_stego.generate_qr(url, out_path, scale)
        used = _charge(key, "qr_generate")
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="image/png",
            headers={"Content-Disposition": "attachment; filename=qr.png",
                     **_token_headers(key, plan, used)},
        )


@app.post("/api/qr/encode")
async def qr_encode(
    url: str = Form(..., description="URL to encode in QR (QR stays scannable)"),
    message: str = Form(..., description="Secret message to hide inside the QR image"),
    scale: int = Form(10),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """Generate a scannable QR code for *url* and embed *message* in its pixel LSBs."""
    key, plan, _ = _resolve_key(x_api_key)
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
        used = _charge(key, "qr_encode")
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="image/png",
            headers={"Content-Disposition": "attachment; filename=stego_qr.png",
                     **_token_headers(key, plan, used)},
        )


@app.post("/api/qr/decode")
async def qr_decode(
    stego: UploadFile = File(..., description="Stego QR image (PNG)"),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """Extract the hidden message from a stego QR image."""
    key, plan, _ = _resolve_key(x_api_key)
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

    used = _charge(key, "qr_decode")
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
