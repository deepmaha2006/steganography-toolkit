"""Smoke-test every steganography module end-to-end."""

import sys
import os
import tempfile
from pathlib import Path

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

SECRET = b"The quick brown fox jumps over the lazy dog"
PASSWORD = "hunter2"


def banner(name): print(f"\n{'='*50}\n  {name}\n{'='*50}")


# ── 1. Crypto ────────────────────────────────────────────────────────────────
banner("Crypto (AES-GCM)")
from stego.crypto import encrypt, decrypt
ct = encrypt(SECRET, PASSWORD)
pt = decrypt(ct, PASSWORD)
assert pt == SECRET, f"Expected {SECRET!r}, got {pt!r}"
print(f"  encrypt/decrypt round-trip  {PASS}")


# ── 2. Image ─────────────────────────────────────────────────────────────────
banner("Image (LSB PNG)")
from stego import image_stego
from PIL import Image
import numpy as np

tmp = Path(tempfile.mkdtemp())
cover = tmp / "cover.png"
stego_img = tmp / "stego.png"

# Create a simple cover image
arr = np.random.randint(0, 256, (200, 300, 3), dtype=np.uint8)
Image.fromarray(arr, "RGB").save(cover)

cap = image_stego.capacity(cover)
print(f"  capacity = {cap} bytes")

image_stego.encode(cover, SECRET, stego_img)
recovered = image_stego.decode(stego_img)
assert recovered == SECRET, f"Expected {SECRET!r}, got {recovered!r}"
print(f"  encode/decode round-trip    {PASS}")

# With encryption
image_stego.encode(cover, encrypt(SECRET, PASSWORD), stego_img)
recovered_enc = decrypt(image_stego.decode(stego_img), PASSWORD)
assert recovered_enc == SECRET
print(f"  encrypted encode/decode     {PASS}")


# ── 3. Audio ─────────────────────────────────────────────────────────────────
banner("Audio (LSB WAV)")
from stego import audio_stego
import soundfile as sf

cover_wav = tmp / "cover.wav"
stego_wav = tmp / "stego.wav"

# Generate 1 second of silence (44100 samples, stereo)
silence = np.zeros((44100, 2), dtype=np.int16)
sf.write(str(cover_wav), silence, 44100, subtype="PCM_16")

cap = audio_stego.capacity(cover_wav)
print(f"  capacity = {cap} bytes")

audio_stego.encode(cover_wav, SECRET, stego_wav)
recovered = audio_stego.decode(stego_wav)
assert recovered == SECRET, f"Expected {SECRET!r}, got {recovered!r}"
print(f"  encode/decode round-trip    {PASS}")


# ── 4. QR ────────────────────────────────────────────────────────────────────
banner("QR (LSB in PNG)")
from stego import qr_stego

qr_img = tmp / "qr.png"
stego_qr = tmp / "stego_qr.png"

qr_stego.generate_qr("https://example.com", qr_img, scale=10)
print(f"  QR generated: {qr_img}")

cap = qr_stego.capacity(qr_img)
print(f"  capacity = {cap} bytes")

qr_stego.encode(qr_img, SECRET, stego_qr)
recovered = qr_stego.decode(stego_qr)
assert recovered == SECRET, f"Expected {SECRET!r}, got {recovered!r}"
print(f"  encode/decode round-trip    {PASS}")


# ── 5. Text (zero-width) ─────────────────────────────────────────────────────
banner("Text (zero-width Unicode)")
from stego import text_stego

cover_text = "Hello, this is an innocent message!"
stego_text = text_stego.encode(cover_text, SECRET)

# Visually the stego text should start with the same first character
assert stego_text[0] == cover_text[0]
print(f"  first char preserved        {PASS}")
print(f"  visible part: {repr(stego_text[:40])}...")

recovered = text_stego.decode(stego_text)
assert recovered == SECRET, f"Expected {SECRET!r}, got {recovered!r}"
print(f"  encode/decode round-trip    {PASS}")


# ── 6. PDF ───────────────────────────────────────────────────────────────────
banner("PDF (invisible text layer)")
from stego import pdf_stego

stego_pdf = tmp / "stego.pdf"
pdf_stego.encode(SECRET, stego_pdf, visible_text="Annual Report 2024")
recovered = pdf_stego.decode(stego_pdf)
assert recovered == SECRET, f"Expected {SECRET!r}, got {recovered!r}"
print(f"  invisible text round-trip   {PASS}")

# Metadata channel
existing_pdf = tmp / "existing.pdf"
pdf_stego.encode(SECRET, existing_pdf, visible_text="Placeholder")  # make one first
meta_out = tmp / "meta_stego.pdf"
pdf_stego.encode_metadata(existing_pdf, SECRET, meta_out)
recovered_meta = pdf_stego.decode_metadata(meta_out)
assert recovered_meta == SECRET
print(f"  metadata channel round-trip {PASS}")


# ── 7. Git ───────────────────────────────────────────────────────────────────
banner("Git (timestamp + whitespace channels)")
import git as gitpython
import shutil

repo_dir = tmp / "testrepo"
repo_dir.mkdir()
repo = gitpython.Repo.init(str(repo_dir))
repo.config_writer().set_value("user", "name", "Tester").release()
repo.config_writer().set_value("user", "email", "test@test.com").release()

SHORT_SECRET = b"Hi!"  # keep it short so few commits needed

from stego import git_stego

# Timestamp channel
n = git_stego.encode(str(repo_dir), SHORT_SECRET, channel="timestamp")
print(f"  timestamp: created {n} commits")
recovered = git_stego.decode(str(repo_dir), channel="timestamp")
assert recovered == SHORT_SECRET, f"Expected {SHORT_SECRET!r}, got {recovered!r}"
print(f"  timestamp channel round-trip {PASS}")

# Whitespace channel
n2 = git_stego.encode(str(repo_dir), SHORT_SECRET, channel="whitespace")
print(f"  whitespace: created {n2} commits")
# (decode will also read the extra commits; use num_commits to scope to whitespace only)
recovered2 = git_stego.decode(str(repo_dir), channel="whitespace", num_commits=n2)
assert recovered2 == SHORT_SECRET, f"Expected {SHORT_SECRET!r}, got {recovered2!r}"
print(f"  whitespace channel round-trip {PASS}")


# ── Summary ──────────────────────────────────────────────────────────────────
banner("ALL TESTS PASSED")
shutil.rmtree(tmp, ignore_errors=True)
