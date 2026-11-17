"""
Audio steganography — LSB encoding in WAV / FLAC / AIFF / MP3 sample data.

Supported INPUT formats : WAV, FLAC, AIFF, MP3
Supported OUTPUT formats: WAV, FLAC, AIFF  (lossless only — MP3 re-encoding
                           destroys LSB data, so MP3 input is decoded to WAV)

Header layout (identical to image_stego):
  Bits 0-31  : payload length (uint32, big-endian)
  Bits 32-N  : payload bytes

Capacity: (total_samples - 32) // 8 bytes
  e.g. a 30-second 44.1 kHz stereo WAV yields ~330 KB payload capacity.
"""

import struct
from pathlib import Path

import numpy as np
import soundfile as sf

SUPPORTED_INPUT = {".wav", ".flac", ".aiff", ".mp3"}
SUPPORTED_OUTPUT = {".wav", ".flac", ".aiff"}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB hard limit

# Magic-byte signatures for format verification
_MAGIC = {
    ".wav":  (b"RIFF", b"WAVE"),  # checked at [0:4] and [8:12]
    ".flac": (b"fLaC",),
    ".aiff": (b"FORM", b"AIFF"),
    ".mp3":  None,                 # variable; pydub handles validation
}


def _validate_input(path: Path) -> None:
    """Raise on missing file, oversized file, or unsupported extension."""
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path.name}")
    size = path.stat().st_size
    if size == 0:
        raise ValueError("Input file is empty")
    if size > MAX_FILE_SIZE:
        raise ValueError(f"Input file exceeds {MAX_FILE_SIZE // 1024 // 1024} MB limit")
    if path.suffix.lower() not in SUPPORTED_INPUT:
        raise ValueError(
            f"Unsupported audio format '{path.suffix}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_INPUT))}"
        )


def _validate_magic(path: Path) -> None:
    """Check magic bytes for WAV / FLAC / AIFF."""
    suffix = path.suffix.lower()
    if suffix == ".mp3":
        return  # pydub validates MP3 internally
    sigs = _MAGIC.get(suffix)
    if not sigs:
        return
    with open(path, "rb") as fh:
        header = fh.read(12)
    if suffix in {".wav", ".aiff"}:
        if not (header[:4] == sigs[0] and header[8:12] == sigs[1]):
            raise ValueError(f"File does not appear to be a valid {suffix.upper()}")
    elif suffix == ".flac":
        if header[:4] != sigs[0]:
            raise ValueError("File does not appear to be a valid FLAC")


def _load_audio(path: Path) -> tuple[np.ndarray, int]:
    """Return (samples_int16_always_2d, samplerate). Handles MP3 via pydub."""
    if path.suffix.lower() == ".mp3":
        try:
            from pydub import AudioSegment  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError(
                "pydub is required for MP3 support — install it with:\n"
                "  pip install pydub\n"
                "  # and ensure ffmpeg is installed on your system"
            )
        seg = AudioSegment.from_mp3(str(path)).set_sample_width(2)  # → 16-bit PCM
        samplerate = seg.frame_rate
        channels = seg.channels
        raw = np.frombuffer(seg.raw_data, dtype=np.int16)
        return raw.reshape(-1, channels), samplerate

    return sf.read(str(path), dtype="int16", always_2d=True)


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


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def capacity(audio_path: str | Path) -> int:
    """Return the maximum payload size in bytes for *audio_path*."""
    p = Path(audio_path)
    _validate_input(p)
    if p.suffix.lower() == ".mp3":
        try:
            from pydub import AudioSegment  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError("pydub is required for MP3 capacity queries")
        seg = AudioSegment.from_mp3(str(p))
        total_samples = int(seg.frame_count()) * seg.channels
    else:
        info = sf.info(str(p))
        total_samples = info.frames * info.channels
    return max(0, (total_samples - 32) // 8)


def encode(audio_path: str | Path, payload: bytes, output_path: str | Path) -> None:
    """Embed *payload* into *audio_path* and write lossless result to *output_path*.

    MP3 input is accepted and decoded to PCM.  The output must be a lossless
    format (.wav, .flac, .aiff) because lossy re-encoding destroys hidden bits.
    """
    p = Path(audio_path)
    out = Path(output_path)

    _validate_input(p)
    _validate_magic(p)

    if out.suffix.lower() not in SUPPORTED_OUTPUT:
        raise ValueError(
            f"Output must be lossless ({', '.join(sorted(SUPPORTED_OUTPUT))}) — "
            "MP3 re-encoding would destroy hidden data"
        )

    if not isinstance(payload, (bytes, bytearray)) or len(payload) == 0:
        raise ValueError("Payload must be a non-empty bytes object")

    data, samplerate = _load_audio(p)
    flat = data.flatten()
    max_bytes = (len(flat) - 32) // 8
    if len(payload) > max_bytes:
        raise ValueError(
            f"Payload too large: {len(payload):,} bytes "
            f"(capacity {max_bytes:,} bytes)"
        )

    bit_stream = (
        list(_bits_from_bytes(struct.pack(">I", len(payload))))
        + list(_bits_from_bytes(payload))
    )

    for i, bit in enumerate(bit_stream):
        flat[i] = (int(flat[i]) & ~1) | bit

    result = flat.reshape(data.shape).astype(np.int16)
    sf.write(str(out), result, samplerate, subtype="PCM_16")


def decode(audio_path: str | Path) -> bytes:
    """Extract and return the hidden payload from *audio_path*."""
    p = Path(audio_path)
    _validate_input(p)
    _validate_magic(p)

    data, _ = _load_audio(p)
    flat = data.flatten()

    if len(flat) < 32:
        raise ValueError("Audio file too short to contain a payload header")

    bits = [int(s) & 1 for s in flat[:32]]
    length = struct.unpack(">I", _bytes_from_bits(bits))[0]
    if length == 0 or length > 100_000_000:
        raise ValueError("No valid steganographic payload found")

    total = 32 + length * 8
    if total > len(flat):
        raise ValueError("Declared payload length exceeds available samples — file may be corrupt")

    bits += [int(flat[i]) & 1 for i in range(32, total)]
    return _bytes_from_bits(bits[32: 32 + length * 8])
