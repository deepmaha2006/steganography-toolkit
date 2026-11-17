"""
Zero-width Unicode text steganography.

Invisible characters used
--------------------------
  U+200B  ZERO WIDTH SPACE        → bit 0
  U+200C  ZERO WIDTH NON-JOINER   → bit 1

Framing characters
------------------
  U+200D  ZERO WIDTH JOINER       → marks start and end of hidden segment

Binary data is serialised as:
  U+200D  <32 length bits as 200B/200C>  <payload bits as 200B/200C>  U+200D

The invisible sequence is inserted after the first visible character of the
cover text, making it undetectable in any messaging platform that renders
Unicode text normally (Discord, Slack, WhatsApp, plain-text editors, …).
"""

ZWS = "​"   # bit 0
ZWNJ = "‌"  # bit 1
ZWJ = "‍"   # frame marker


# ---------------------------------------------------------------------------
# helpers
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


def _bits_to_zw(bits) -> str:
    return "".join(ZWS if b == 0 else ZWNJ for b in bits)


def _zw_to_bits(text: str) -> list[int]:
    return [0 if ch == ZWS else 1 for ch in text if ch in (ZWS, ZWNJ)]


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def encode(cover_text: str, payload: bytes) -> str:
    """Embed *payload* invisibly inside *cover_text*."""
    import struct
    header_bits = list(_bits_from_bytes(struct.pack(">I", len(payload))))
    payload_bits = list(_bits_from_bytes(payload))
    hidden = ZWJ + _bits_to_zw(header_bits + payload_bits) + ZWJ

    if not cover_text:
        return hidden
    # Insert after first visible character
    return cover_text[0] + hidden + cover_text[1:]


def decode(stego_text: str) -> bytes:
    """Extract the hidden payload from *stego_text*."""
    import struct
    start = stego_text.find(ZWJ)
    if start == -1:
        raise ValueError("No hidden payload marker found")
    end = stego_text.find(ZWJ, start + 1)
    if end == -1:
        raise ValueError("Incomplete payload marker")

    segment = stego_text[start + 1:end]
    bits = _zw_to_bits(segment)

    if len(bits) < 32:
        raise ValueError("Payload too short to contain length header")

    length = struct.unpack(">I", _bytes_from_bits(bits[:32]))[0]
    return _bytes_from_bits(bits[32: 32 + length * 8])


def capacity(cover_text: str) -> str:
    """Zero-width text has no inherent capacity limit; return an informational string."""
    return "Unlimited — hidden bits do not consume visible characters"
