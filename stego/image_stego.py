"""
Image steganography — LSB encoding in PNG/BMP pixel data.

Layout inside the image:
  Bits 0-31  : payload length (uint32, big-endian)
  Bits 32-N  : payload bytes

Capacity = (W × H × 3 - 32) // 8 bytes  (one bit per RGB channel).
"""

import struct
from pathlib import Path

from PIL import Image

SUPPORTED_INPUT = {".png", ".bmp"}
SUPPORTED_OUTPUT = {".png", ".bmp"}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
_MAX_DIMENSION = 65_535             # sane upper bound for W/H

_MAGIC = {
    ".png": b"\x89PNG\r\n\x1a\n",
    ".bmp": b"BM",
}


def _validate_input(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path.name}")
    size = path.stat().st_size
    if size == 0:
        raise ValueError("Input file is empty")
    if size > MAX_FILE_SIZE:
        raise ValueError(f"Input file exceeds {MAX_FILE_SIZE // 1024 // 1024} MB limit")
    if path.suffix.lower() not in SUPPORTED_INPUT:
        raise ValueError(
            f"Unsupported image format '{path.suffix}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_INPUT))}"
        )


def _validate_magic(path: Path) -> None:
    sig = _MAGIC.get(path.suffix.lower())
    if sig is None:
        return
    with open(path, "rb") as fh:
        header = fh.read(len(sig))
    if header != sig:
        raise ValueError(f"File does not appear to be a valid {path.suffix.upper()}")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _iter_pixels(img: Image.Image):
    """Yield (x, y) for every pixel in row-major order."""
    w, h = img.size
    for y in range(h):
        for x in range(w):
            yield x, y


def _bits_from_bytes(data: bytes):
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _bytes_from_bits(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if len(chunk) < 8:
            break
        out.append(int("".join(map(str, chunk)), 2))
    return bytes(out)


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def capacity(image_path: str | Path) -> int:
    """Return the maximum payload size in bytes for *image_path*."""
    p = Path(image_path)
    _validate_input(p)
    img = Image.open(p).convert("RGB")
    w, h = img.size
    return max(0, (w * h * 3 - 32) // 8)


def encode(image_path: str | Path, payload: bytes, output_path: str | Path) -> None:
    """Embed *payload* into *image_path* and write the result to *output_path*."""
    p = Path(image_path)
    out = Path(output_path)

    _validate_input(p)
    _validate_magic(p)

    if out.suffix.lower() not in SUPPORTED_OUTPUT:
        raise ValueError(
            f"Output must be lossless ({', '.join(sorted(SUPPORTED_OUTPUT))}) — "
            "JPEG/WebP would destroy hidden data"
        )

    if not isinstance(payload, (bytes, bytearray)) or len(payload) == 0:
        raise ValueError("Payload must be a non-empty bytes object")

    img = Image.open(p).convert("RGB")
    w, h = img.size
    max_bytes = (w * h * 3 - 32) // 8
    if len(payload) > max_bytes:
        raise ValueError(
            f"Payload too large: {len(payload):,} bytes "
            f"(capacity {max_bytes:,} bytes)"
        )

    pixels = img.load()
    bit_stream = (
        list(_bits_from_bytes(struct.pack(">I", len(payload))))
        + list(_bits_from_bytes(payload))
    )

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

    img.save(out)


def decode(image_path: str | Path) -> bytes:
    """Extract and return the hidden payload from *image_path*."""
    p = Path(image_path)
    _validate_input(p)
    _validate_magic(p)

    img = Image.open(p).convert("RGB")
    pixels = img.load()

    bits: list[int] = []
    pix_iter = _iter_pixels(img)

    for x, y in pix_iter:
        r, g, b = pixels[x, y]
        for ch in (r, g, b):
            bits.append(ch & 1)
        if len(bits) >= 32:
            break

    if len(bits) < 32:
        raise ValueError("Image too small to contain a payload header")

    length = struct.unpack(">I", _bytes_from_bits(bits[:32]))[0]
    if length == 0 or length > 100_000_000:
        raise ValueError("No valid steganographic payload found")

    total_bits_needed = 32 + length * 8
    for x, y in pix_iter:
        if len(bits) >= total_bits_needed:
            break
        r, g, b = pixels[x, y]
        for ch in (r, g, b):
            bits.append(ch & 1)

    return _bytes_from_bits(bits[32: 32 + length * 8])
