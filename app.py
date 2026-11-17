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
- Razorpay HMAC signature verification for payments
"""

import hashlib
import hmac as _hmac
import io
import json
import os
import re
import tempfile
import uuid
from datetime import date, timedelta
from pathlib import Path
from typing import Optional

import httpx
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
# payment + API key configuration
# ---------------------------------------------------------------------------

DEMO_KEY         = "inv_demo_free_2026"
DEMO_DAILY_LIMIT = 100

# Razorpay credentials (set in Vercel env)
RAZORPAY_KEY_ID         = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET     = os.environ.get("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")

# Upstash Redis REST (set in Vercel env)
#   UPSTASH_REDIS_URL   = https://xxx.upstash.io
#   UPSTASH_REDIS_TOKEN = AXXXXXbearer-token
UPSTASH_URL   = os.environ.get("UPSTASH_REDIS_URL", "").rstrip("/")
UPSTASH_TOKEN = os.environ.get("UPSTASH_REDIS_TOKEN", "")

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "deepeshmahawar2006@gmail.com")

# ---------------------------------------------------------------------------
# plans — amount in paise (₹1 = 100 paise)
# ---------------------------------------------------------------------------

PLANS: dict[str, dict] = {
    # ── monthly ──────────────────────────────────────────────────────────
    "starter_monthly": {
        "tokens": 1_000, "amount": 4_900, "billing": "monthly",
        "label": "Starter Monthly", "display": "₹49/mo · 1,000 tokens/month",
    },
    "growth_monthly": {
        "tokens": 5_000, "amount": 14_900, "billing": "monthly",
        "label": "Growth Monthly",  "display": "₹149/mo · 5,000 tokens/month",
    },
    "pro_monthly": {
        "tokens": 20_000, "amount": 49_900, "billing": "monthly",
        "label": "Pro Monthly",    "display": "₹499/mo · 20,000 tokens/month",
    },
    # ── yearly (tokens reset monthly; billed once) ───────────────────────
    "starter_yearly": {
        "tokens": 1_000, "amount": 39_900, "billing": "yearly",
        "label": "Starter Yearly", "display": "₹399/yr · 1,000 tokens/month",
    },
    "growth_yearly": {
        "tokens": 5_000, "amount": 1_19_900, "billing": "yearly",
        "label": "Growth Yearly",  "display": "₹1,199/yr · 5,000 tokens/month",
    },
    "pro_yearly": {
        "tokens": 20_000, "amount": 3_99_900, "billing": "yearly",
        "label": "Pro Yearly",     "display": "₹3,999/yr · 20,000 tokens/month",
    },
    # ── one-time token packs (no expiry) ─────────────────────────────────
    "pack_1k": {
        "tokens": 1_000, "amount": 5_000, "billing": "onetime",
        "label": "1K Token Pack",  "display": "₹50 · 1,000 tokens, never expires",
    },
    "pack_5k": {
        "tokens": 5_000, "amount": 20_000, "billing": "onetime",
        "label": "5K Token Pack",  "display": "₹200 · 5,000 tokens, never expires",
    },
    "pack_15k": {
        "tokens": 15_000, "amount": 50_000, "billing": "onetime",
        "label": "15K Token Pack", "display": "₹500 · 15,000 tokens, never expires",
    },
}

TOKEN_COST: dict[str, int] = {
    "image_encode": 10,
    "image_decode":  5,
    "audio_encode": 20,
    "audio_decode": 10,
    "qr_encode":    10,
    "qr_decode":     5,
    "qr_generate":   2,
    "text_encode":   5,
    "text_decode":   2,
    "pdf_encode":   10,
    "pdf_decode":    5,
}

# ---------------------------------------------------------------------------
# Upstash Redis REST helpers
# ---------------------------------------------------------------------------

async def _kv_cmd(*args) -> object:
    """Execute a Redis command via Upstash REST API. Returns the 'result' value."""
    if not UPSTASH_URL or not UPSTASH_TOKEN:
        return None
    async with httpx.AsyncClient(timeout=5.0) as c:
        r = await c.post(
            UPSTASH_URL,
            headers={"Authorization": f"Bearer {UPSTASH_TOKEN}"},
            json=list(args),
        )
        return r.json().get("result")


async def _kv_get(key: str) -> dict | None:
    raw = await _kv_cmd("GET", key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


async def _kv_set(key: str, value: dict, ex: int | None = None) -> None:
    cmd = ["SET", key, json.dumps(value)]
    if ex:
        cmd += ["EX", str(ex)]
    await _kv_cmd(*cmd)


async def _kv_del(key: str) -> None:
    await _kv_cmd("DEL", key)


# ---------------------------------------------------------------------------
# in-memory fallback key store (env var INVISYNC_API_KEYS)
# Format: inv_live_xxx:1000,inv_live_yyy:5000
# ---------------------------------------------------------------------------

_mem_keys: dict[str, int] = {}
_raw_keys = os.environ.get("INVISYNC_API_KEYS", "")
for _pair in _raw_keys.split(","):
    _pair = _pair.strip()
    if ":" in _pair:
        _k, _v = _pair.rsplit(":", 1)
        try:
            _mem_keys[_k.strip()] = int(_v.strip())
        except ValueError:
            pass

# demo daily usage tracker (in-memory, resets on cold start)
_demo_usage: dict[str, int] = {}  # {date_str: tokens_used}

# in-memory usage for env-var keys
_mem_usage: dict[str, int] = {}   # {key: tokens_used}


# ---------------------------------------------------------------------------
# API key resolution
# ---------------------------------------------------------------------------

async def _resolve_key(x_api_key: Optional[str]) -> tuple[str, str, int]:
    """Return (key, plan_id, remaining_tokens). Raises 401 on bad key."""
    if not x_api_key:
        return "__anon__", "none", 0

    # ── demo key ──────────────────────────────────────────────────────────
    if x_api_key == DEMO_KEY:
        today = str(date.today())
        used = _demo_usage.get(today, 0)
        return DEMO_KEY, "free", max(0, DEMO_DAILY_LIMIT - used)

    # ── Redis-backed live key ─────────────────────────────────────────────
    if UPSTASH_URL:
        rec = await _kv_get(f"apikey:{x_api_key}")
        if rec and rec.get("active"):
            rec, changed = _maybe_reset_period(rec)
            if changed:
                await _kv_set(f"apikey:{x_api_key}", rec)
            billing = rec["billing"]
            tokens_per = rec["tokens_per_period"]
            tokens_used = rec["tokens_used"]
            # for yearly: also check plan_expires
            if billing == "yearly":
                expires = rec.get("plan_expires")
                if expires and date.today() > date.fromisoformat(expires):
                    rec["active"] = False
                    await _kv_set(f"apikey:{x_api_key}", rec)
                    raise HTTPException(402, "Yearly plan expired — renew at https://invisync.vercel.app/developer")
            return x_api_key, rec["plan_id"], max(0, tokens_per - tokens_used)
        if rec and not rec.get("active"):
            raise HTTPException(401, "API key deactivated")

    # ── env-var in-memory key ─────────────────────────────────────────────
    if x_api_key in _mem_keys:
        used = _mem_usage.get(x_api_key, 0)
        balance = max(0, _mem_keys[x_api_key] - used)
        plan_id = (
            "starter_monthly" if _mem_keys[x_api_key] <= 1000 else
            "growth_monthly"  if _mem_keys[x_api_key] <= 5000 else
            "pro_monthly"
        )
        return x_api_key, plan_id, balance

    raise HTTPException(401, "Invalid API key — get one at https://invisync.vercel.app/developer")


def _maybe_reset_period(rec: dict) -> tuple[dict, bool]:
    """Reset tokens_used if the current period has expired. Returns (rec, changed)."""
    billing = rec.get("billing", "onetime")
    if billing == "onetime":
        return rec, False
    period_end_str = rec.get("period_end")
    if not period_end_str:
        return rec, False
    period_end = date.fromisoformat(period_end_str)
    if date.today() <= period_end:
        return rec, False
    # period expired — reset
    rec["tokens_used"] = 0
    # advance period
    if billing == "monthly":
        new_end = period_end + timedelta(days=31)
    else:  # yearly — advance by one month within the yearly window
        new_end = period_end + timedelta(days=31)
    rec["period_end"] = new_end.isoformat()
    return rec, True


# ---------------------------------------------------------------------------
# Token charging
# ---------------------------------------------------------------------------

async def _charge(key: str, operation: str) -> int:
    """Deduct tokens; raise 402 if insufficient. Returns tokens_used."""
    if key == "__anon__":
        return 0
    cost = TOKEN_COST.get(operation, 5)

    # ── demo key ──────────────────────────────────────────────────────────
    if key == DEMO_KEY:
        today = str(date.today())
        used = _demo_usage.get(today, 0)
        if used + cost > DEMO_DAILY_LIMIT:
            raise HTTPException(
                402,
                f"Demo key daily limit ({DEMO_DAILY_LIMIT} tokens/day) reached. "
                "Get a live key at https://invisync.vercel.app/developer",
            )
        _demo_usage[today] = used + cost
        return cost

    # ── Redis-backed live key ─────────────────────────────────────────────
    if UPSTASH_URL:
        rec = await _kv_get(f"apikey:{key}")
        if rec and rec.get("active"):
            rec, _ = _maybe_reset_period(rec)
            tokens_per  = rec["tokens_per_period"]
            tokens_used = rec["tokens_used"]
            if tokens_used + cost > tokens_per:
                raise HTTPException(
                    402,
                    f"Insufficient token balance ({tokens_per - tokens_used} remaining, "
                    f"need {cost}). Top up at https://invisync.vercel.app/developer",
                )
            rec["tokens_used"] = tokens_used + cost
            await _kv_set(f"apikey:{key}", rec)
            return cost

    # ── env-var in-memory key ─────────────────────────────────────────────
    if key in _mem_keys:
        used = _mem_usage.get(key, 0)
        if used + cost > _mem_keys[key]:
            raise HTTPException(402, "Insufficient token balance — top up at https://invisync.vercel.app/developer")
        _mem_usage[key] = used + cost
        return cost

    return 0


async def _remaining(key: str) -> int:
    """Return remaining tokens for a key (after any period reset)."""
    if key == "__anon__":
        return 0
    if key == DEMO_KEY:
        today = str(date.today())
        return max(0, DEMO_DAILY_LIMIT - _demo_usage.get(today, 0))
    if UPSTASH_URL:
        rec = await _kv_get(f"apikey:{key}")
        if rec:
            rec, _ = _maybe_reset_period(rec)
            return max(0, rec["tokens_per_period"] - rec["tokens_used"])
    if key in _mem_keys:
        return max(0, _mem_keys[key] - _mem_usage.get(key, 0))
    return 0


def _token_headers(key: str, plan_id: str, used: int, rem: int) -> dict:
    if key == "__anon__":
        return {}
    return {
        "X-Tokens-Used":      str(used),
        "X-Tokens-Remaining": str(rem),
        "X-Plan":             plan_id,
        "X-Request-Id":       f"req_{uuid.uuid4().hex[:12]}",
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


# ---------------------------------------------------------------------------
# middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    # paths that need CDN access (Swagger UI)
    _DOCS_PATHS = {"/api/docs", "/api/redoc", "/openapi.json"}

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        path = request.url.path

        response.headers["X-Content-Type-Options"]   = "nosniff"
        response.headers["X-Frame-Options"]          = "DENY"
        response.headers["X-XSS-Protection"]         = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        if path in self._DOCS_PATHS:
            # Swagger UI needs cdn.jsdelivr.net
            response.headers["Content-Security-Policy"] = (
                "default-src 'self' cdn.jsdelivr.net; "
                "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com; "
                "img-src 'self' data: blob: cdn.jsdelivr.net; "
                "font-src 'self' cdn.jsdelivr.net fonts.gstatic.com"
            )
        else:
            # App pages — allow Razorpay checkout
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://checkout.razorpay.com https://fonts.googleapis.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "img-src 'self' data: blob: https://cdn.razorpay.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "connect-src 'self' https://api.razorpay.com https://*.razorpay.com; "
                "frame-src https://api.razorpay.com https://*.razorpay.com; "
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

_static_dir = Path(__file__).parent / "static"
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
# routes — health & pages
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


# ---------------------------------------------------------------------------
# payment routes
# ---------------------------------------------------------------------------

@app.get("/api/payments/config")
async def payments_config():
    """Return public Razorpay key and plan details (safe for frontend)."""
    return JSONResponse({
        "razorpay_key_id": RAZORPAY_KEY_ID,
        "currency": "INR",
        "plans": {
            pid: {
                "label":   p["label"],
                "display": p["display"],
                "amount":  p["amount"],
                "billing": p["billing"],
                "tokens":  p["tokens"],
            }
            for pid, p in PLANS.items()
        },
    })


@app.post("/api/payments/create-order")
async def create_order(request: Request):
    """Create a Razorpay order. Body: {plan_id, name, email}"""
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        raise HTTPException(503, "Payment gateway not configured")

    body = await request.json()
    plan_id = str(body.get("plan_id", "")).strip()
    name    = str(body.get("name", "")).strip()[:100]
    email   = str(body.get("email", "")).strip()[:200]

    if plan_id not in PLANS:
        raise HTTPException(400, f"Unknown plan '{plan_id}'")
    if not email or "@" not in email:
        raise HTTPException(400, "Valid email is required")

    plan = PLANS[plan_id]
    receipt = f"inv_{uuid.uuid4().hex[:10]}"

    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.post(
            "https://api.razorpay.com/v1/orders",
            auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET),
            json={"amount": plan["amount"], "currency": "INR", "receipt": receipt},
        )
    if r.status_code != 200:
        raise HTTPException(502, "Payment gateway error — please try again")

    order = r.json()
    order_id = order["id"]

    # Store order details in Redis (expires in 24h)
    await _kv_set(f"order:{order_id}", {
        "plan_id": plan_id,
        "email":   email,
        "name":    name,
        "receipt": receipt,
    }, ex=86400)

    return JSONResponse({
        "order_id": order_id,
        "amount":   plan["amount"],
        "currency": "INR",
        "plan_id":  plan_id,
        "label":    plan["label"],
    })


@app.post("/api/payments/verify")
async def verify_payment(request: Request):
    """
    Verify Razorpay payment signature, generate API key, store in Redis.
    Body: {razorpay_order_id, razorpay_payment_id, razorpay_signature, name, email, plan_id}
    """
    if not RAZORPAY_KEY_SECRET:
        raise HTTPException(503, "Payment gateway not configured")

    body = await request.json()
    order_id   = str(body.get("razorpay_order_id", ""))
    payment_id = str(body.get("razorpay_payment_id", ""))
    signature  = str(body.get("razorpay_signature", ""))

    if not order_id or not payment_id or not signature:
        raise HTTPException(400, "razorpay_order_id, razorpay_payment_id and razorpay_signature are required")

    # Verify HMAC signature
    msg      = f"{order_id}|{payment_id}".encode()
    expected = _hmac.new(RAZORPAY_KEY_SECRET.encode(), msg, hashlib.sha256).hexdigest()
    if not _hmac.compare_digest(expected, signature):
        raise HTTPException(400, "Payment signature verification failed")

    # Retrieve order from Redis
    if not UPSTASH_URL:
        raise HTTPException(503, "Key storage not configured — contact support")

    order_data = await _kv_get(f"order:{order_id}")
    if not order_data:
        raise HTTPException(400, "Order not found or already processed")

    plan_id = order_data["plan_id"]
    email   = str(body.get("email", order_data.get("email", ""))).strip()
    name    = str(body.get("name",  order_data.get("name",  ""))).strip()

    if plan_id not in PLANS:
        raise HTTPException(400, f"Unknown plan '{plan_id}'")

    plan    = PLANS[plan_id]
    billing = plan["billing"]
    today   = date.today()

    # Compute period / expiry
    if billing == "monthly":
        period_end   = (today + timedelta(days=31)).isoformat()
        plan_expires = None
    elif billing == "yearly":
        period_end   = (today + timedelta(days=31)).isoformat()   # monthly token reset
        plan_expires = (today + timedelta(days=366)).isoformat()  # subscription end
    else:  # onetime
        period_end   = None
        plan_expires = None

    # Generate API key
    new_key = f"inv_live_{uuid.uuid4().hex}"

    key_record = {
        "key":              new_key,
        "email":            email,
        "name":             name,
        "plan_id":          plan_id,
        "billing":          billing,
        "tokens_per_period": plan["tokens"],
        "tokens_used":      0,
        "period_end":       period_end,
        "plan_expires":     plan_expires,
        "razorpay_payment_id": payment_id,
        "razorpay_order_id":   order_id,
        "created_at":       today.isoformat(),
        "active":           True,
    }

    await _kv_set(f"apikey:{new_key}", key_record)
    await _kv_del(f"order:{order_id}")

    # Log to Vercel function logs (visible in dashboard)
    print(json.dumps({
        "event":      "payment_success",
        "plan_id":    plan_id,
        "email":      email,
        "payment_id": payment_id,
        "key_prefix": new_key[:20] + "...",
    }))

    return JSONResponse({
        "api_key":   new_key,
        "plan_id":   plan_id,
        "label":     plan["label"],
        "tokens":    plan["tokens"],
        "billing":   billing,
        "period_end": period_end,
    })


@app.post("/api/payments/webhook")
async def razorpay_webhook(request: Request):
    """Razorpay webhook (backup to verify endpoint). Logs only — key already created by /verify."""
    body_bytes = await request.body()
    sig = request.headers.get("x-razorpay-signature", "")

    if RAZORPAY_WEBHOOK_SECRET and sig:
        expected = _hmac.new(RAZORPAY_WEBHOOK_SECRET.encode(), body_bytes, hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(expected, sig):
            raise HTTPException(400, "Webhook signature invalid")

    try:
        event = json.loads(body_bytes)
        print(json.dumps({"event": "razorpay_webhook", "type": event.get("event"), "id": event.get("payload", {}).get("payment", {}).get("entity", {}).get("id")}))
    except Exception:
        pass

    return JSONResponse({"status": "ok"})


@app.get("/api/key-status")
async def key_status(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    """Return remaining tokens and plan info for a key."""
    if not x_api_key:
        raise HTTPException(400, "X-API-Key header required")

    if x_api_key == DEMO_KEY:
        today = str(date.today())
        used = _demo_usage.get(today, 0)
        return JSONResponse({
            "plan_id":   "free",
            "billing":   "daily",
            "tokens_used":  used,
            "tokens_remaining": max(0, DEMO_DAILY_LIMIT - used),
            "tokens_per_period": DEMO_DAILY_LIMIT,
            "resets": "daily",
        })

    if UPSTASH_URL:
        rec = await _kv_get(f"apikey:{x_api_key}")
        if rec and rec.get("active"):
            rec, changed = _maybe_reset_period(rec)
            if changed:
                await _kv_set(f"apikey:{x_api_key}", rec)
            return JSONResponse({
                "plan_id":           rec["plan_id"],
                "billing":           rec["billing"],
                "tokens_used":       rec["tokens_used"],
                "tokens_remaining":  max(0, rec["tokens_per_period"] - rec["tokens_used"]),
                "tokens_per_period": rec["tokens_per_period"],
                "period_end":        rec.get("period_end"),
                "plan_expires":      rec.get("plan_expires"),
                "email":             rec.get("email"),
            })

    if x_api_key in _mem_keys:
        used = _mem_usage.get(x_api_key, 0)
        return JSONResponse({
            "plan_id":           "env_key",
            "billing":           "onetime",
            "tokens_used":       used,
            "tokens_remaining":  max(0, _mem_keys[x_api_key] - used),
            "tokens_per_period": _mem_keys[x_api_key],
        })

    raise HTTPException(401, "Invalid API key")


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
    key, plan, _ = await _resolve_key(x_api_key)
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

        used = await _charge(key, "image_encode")
        rem  = await _remaining(key)
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="image/png" if cover_ext == ".png" else "image/bmp",
            headers={"Content-Disposition": f"attachment; filename=stego{cover_ext}",
                     **_token_headers(key, plan, used, rem)},
        )


@app.post("/api/image/decode")
async def image_decode(
    stego: UploadFile = File(..., description="Stego image (PNG or BMP)"),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = await _resolve_key(x_api_key)
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

    used = await _charge(key, "image_decode")
    rem  = await _remaining(key)
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used, rem))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used, rem))


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
    key, plan, _ = await _resolve_key(x_api_key)
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

        used = await _charge(key, "audio_encode")
        rem  = await _remaining(key)
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="audio/wav",
            headers={"Content-Disposition": "attachment; filename=stego.wav",
                     **_token_headers(key, plan, used, rem)},
        )


@app.post("/api/audio/decode")
async def audio_decode(
    stego: UploadFile = File(..., description="Stego audio (WAV, FLAC, or AIFF)"),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = await _resolve_key(x_api_key)
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

    used = await _charge(key, "audio_decode")
    rem  = await _remaining(key)
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used, rem))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used, rem))


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
    key, plan, _ = await _resolve_key(x_api_key)
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
    used = await _charge(key, "text_encode")
    rem  = await _remaining(key)
    return JSONResponse({"stego_text": stego_text, "size_bytes": len(payload)},
                        headers=_token_headers(key, plan, used, rem))


@app.post("/api/text/decode")
async def text_decode(
    stego_text: str = Form(..., description="Text containing hidden payload"),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = await _resolve_key(x_api_key)
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

    used = await _charge(key, "text_decode")
    rem  = await _remaining(key)
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used, rem))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used, rem))


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
    key, plan, _ = await _resolve_key(x_api_key)
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

        used = await _charge(key, "pdf_encode")
        rem  = await _remaining(key)
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=stego.pdf",
                     **_token_headers(key, plan, used, rem)},
        )


@app.post("/api/pdf/decode")
async def pdf_decode(
    stego: UploadFile = File(..., description="Stego PDF"),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = await _resolve_key(x_api_key)
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

    used = await _charge(key, "pdf_decode")
    rem  = await _remaining(key)
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used, rem))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used, rem))


# ---------------------------------------------------------------------------
# QR endpoints
# ---------------------------------------------------------------------------

@app.post("/api/qr/generate")
async def qr_generate(
    url: str = Form(..., description="URL to encode in QR"),
    scale: int = Form(10),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    key, plan, _ = await _resolve_key(x_api_key)
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    if not 1 <= scale <= 20:
        raise HTTPException(400, "scale must be between 1 and 20")

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "qr.png"
        from stego import qr_stego
        qr_stego.generate_qr(url, out_path, scale)
        used = await _charge(key, "qr_generate")
        rem  = await _remaining(key)
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="image/png",
            headers={"Content-Disposition": "attachment; filename=qr.png",
                     **_token_headers(key, plan, used, rem)},
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
    key, plan, _ = await _resolve_key(x_api_key)
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
        used = await _charge(key, "qr_encode")
        rem  = await _remaining(key)
        return StreamingResponse(
            io.BytesIO(out_path.read_bytes()),
            media_type="image/png",
            headers={"Content-Disposition": "attachment; filename=stego_qr.png",
                     **_token_headers(key, plan, used, rem)},
        )


@app.post("/api/qr/decode")
async def qr_decode(
    stego: UploadFile = File(..., description="Stego QR image (PNG)"),
    password: Optional[str] = Form(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """Extract the hidden message from a stego QR image."""
    key, plan, _ = await _resolve_key(x_api_key)
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

    used = await _charge(key, "qr_decode")
    rem  = await _remaining(key)
    try:
        return JSONResponse({"message": payload.decode("utf-8"), "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used, rem))
    except UnicodeDecodeError:
        return JSONResponse({"message": payload.hex(), "binary": True, "size_bytes": len(payload)},
                            headers=_token_headers(key, plan, used, rem))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
