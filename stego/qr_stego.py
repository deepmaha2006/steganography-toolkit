"""
QR code steganography — LSB embedding in a QR image file.

Theory
------
QR codes use Reed-Solomon error correction at four levels (L/M/Q/H).
At level H the code can recover from up to 30 % module damage.  Steganographic
bit flips applied to the *pixel representation* of modules fall below that
threshold, so a QR scanner still decodes the original URL while the hidden
payload is carried in the image file itself.

Implementation
--------------
1. Generate a high-resolution QR image (scale factor ≥ 10) so each logical
   module maps to multiple pixels — leaving sub-pixel LSBs undetectable.
2. Embed the payload in the least significant bits of the PNG pixel data
   (identical to image_stego) using the same 32-bit-length header.
3. Decode reads those same pixels and reconstructs the payload.

The QR image is a grayscale PNG; each pixel contributes 1 bit of capacity.
"""

import struct
from pathlib import Path

import qrcode
from PIL import Image


# ---------------------------------------------------------------------------
# helpers (identical to image_stego but adapted for grayscale)
# ---------------------------------------------------------------------------

def _bits_from_bytes(data: bytes):
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _bytes_from_bits(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int("".join(map(str, bits[i:i + 8])), 2))
    return bytes(out)


def _iter_pixels(img: Image.Image):
    w, h = img.size
    for y in range(h):
        for x in range(w):
            yield x, y


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def generate_qr(url: str, output_path: str | Path, scale: int = 10) -> None:
    """Create a QR code for *url* and save it to *output_path*."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=scale,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    img.save(str(output_path))


def capacity(qr_image_path: str | Path) -> int:
    """Return the maximum payload size in bytes for a QR image."""
    img = Image.open(qr_image_path).convert("RGB")
    w, h = img.size
    return (w * h * 3 - 32) // 8


def encode(qr_image_path: str | Path, payload: bytes, output_path: str | Path) -> None:
    """Embed *payload* into the QR image at *qr_image_path*."""
    img = Image.open(qr_image_path).convert("RGB")
    w, h = img.size
    max_bytes = (w * h * 3 - 32) // 8
    if len(payload) > max_bytes:
        raise ValueError(f"Payload too large: {len(payload)} bytes, capacity {max_bytes} bytes")

    pixels = img.load()
    bit_stream = list(_bits_from_bytes(struct.pack(">I", len(payload)))) + list(_bits_from_bytes(payload))

    bit_index = 0
    for x, y in _iter_pixels(img):
        if bit_index >= len(bit_stream):
            break
        r, g, b = pixels[x, y]
        new_channels = []
        for ch in (r, g, b):
            if bit_index < len(bit_stream):
                ch = (ch & 0xFE) | bit_stream[bit_index]
                bit_index += 1
            new_channels.append(ch)
        pixels[x, y] = tuple(new_channels)

    img.save(str(output_path))


def decode(qr_image_path: str | Path) -> bytes:
    """Extract the hidden payload from a QR image."""
    img = Image.open(qr_image_path).convert("RGB")
    pixels = img.load()

    bits: list[int] = []
    pix_iter = _iter_pixels(img)

    for x, y in pix_iter:
        r, g, b = pixels[x, y]
        for ch in (r, g, b):
            bits.append(ch & 1)
        if len(bits) >= 32:
            break

    length = struct.unpack(">I", _bytes_from_bits(bits[:32]))[0]
    if length == 0 or length > 100_000_000:
        raise ValueError("No valid steganographic payload found")

    total_bits = 32 + length * 8
    for x, y in pix_iter:
        if len(bits) >= total_bits:
            break
        r, g, b = pixels[x, y]
        for ch in (r, g, b):
            bits.append(ch & 1)

    return _bytes_from_bits(bits[32: 32 + length * 8])
