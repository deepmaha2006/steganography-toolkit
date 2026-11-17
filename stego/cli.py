"""
Invisync — CLI for the professional steganography toolkit.

Usage examples
--------------
  # Image (PNG / BMP)
  python -m stego image encode --input photo.png --message "secret" --output out.png
  python -m stego image encode --input photo.png --file secret.bin --output out.png --password mypass
  python -m stego image decode --input out.png --password mypass

  # Audio (WAV / FLAC / AIFF / MP3)
  python -m stego audio encode --input song.wav --message "hello" --output out.wav
  python -m stego audio encode --input song.mp3 --message "hello" --output out.wav
  python -m stego audio decode --input out.wav

  # QR
  python -m stego qr generate --url https://example.com --output qr.png
  python -m stego qr encode  --input qr.png --message "secret" --output qr_stego.png
  python -m stego qr decode  --input qr_stego.png

  # Text (zero-width Unicode)
  python -m stego text encode --cover "Hello world" --message "secret" --output stego.txt
  python -m stego text decode --input stego.txt

  # PDF
  python -m stego pdf encode --message "secret" --output out.pdf
  python -m stego pdf encode --input existing.pdf --message "secret" --output out.pdf
  python -m stego pdf decode --input out.pdf

  # Git
  python -m stego git encode --repo /path/to/repo --message "secret"
  python -m stego git decode --repo /path/to/repo --channel timestamp

  # Capacity report
  python -m stego capacity --input photo.png
  python -m stego capacity --input song.wav
  python -m stego capacity --input song.mp3
"""

import sys
import click

from . import crypto


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _get_payload(message: str | None, file: str | None, password: str | None) -> bytes:
    if file and message:
        raise click.UsageError("Provide either --message or --file, not both")
    if file:
        from pathlib import Path
        fp = Path(file)
        if not fp.exists():
            raise click.UsageError(f"File not found: {file}")
        if fp.stat().st_size > 500 * 1024 * 1024:
            raise click.UsageError("Payload file too large (max 500 MB)")
        with open(fp, "rb") as f:
            raw = f.read()
    elif message:
        raw = message.encode("utf-8")
    else:
        raise click.UsageError("Provide --message or --file")

    if password:
        raw = crypto.encrypt(raw, password)
    return raw


def _output_payload(payload: bytes, password: str | None, output: str | None) -> None:
    if password:
        try:
            payload = crypto.decrypt(payload, password)
        except Exception:
            raise click.ClickException("Decryption failed — wrong password or corrupt data")

    if output:
        from pathlib import Path
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as f:
            f.write(payload)
        click.echo(f"Payload written to {out} ({len(payload):,} bytes)")
    else:
        try:
            click.echo(payload.decode("utf-8"))
        except UnicodeDecodeError:
            click.echo(f"[binary payload — {len(payload):,} bytes]")
            click.echo(payload.hex())


# ---------------------------------------------------------------------------
# root
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="invisync")
def cli():
    """Invisync — hide data in images, audio, QR codes, text, PDF, and git commits."""


# ---------------------------------------------------------------------------
# image
# ---------------------------------------------------------------------------

@cli.group()
def image():
    """PNG/BMP image steganography (LSB)."""


@image.command("encode")
@click.option("--input", "inp", required=True, help="Cover image (PNG or BMP)")
@click.option("--output", required=True, help="Output image path (.png or .bmp)")
@click.option("--message", default=None, help="Text payload")
@click.option("--file", "payload_file", default=None, help="Binary payload file")
@click.option("--password", default=None, help="Encrypt payload with this password (AES-256-GCM)")
def image_encode(inp, output, message, payload_file, password):
    from . import image_stego
    payload = _get_payload(message, payload_file, password)
    image_stego.encode(inp, payload, output)
    click.echo(f"Encoded {len(payload):,} bytes into {output}")


@image.command("decode")
@click.option("--input", "inp", required=True, help="Stego image (PNG or BMP)")
@click.option("--password", default=None, help="Decryption password")
@click.option("--output", default=None, help="Write decoded payload to file")
def image_decode(inp, password, output):
    from . import image_stego
    payload = image_stego.decode(inp)
    _output_payload(payload, password, output)


# ---------------------------------------------------------------------------
# audio
# ---------------------------------------------------------------------------

@cli.group()
def audio():
    """WAV/FLAC/AIFF/MP3 audio steganography (LSB on PCM samples).

    Note: output is always a lossless format (.wav/.flac/.aiff) because
    MP3 re-encoding destroys least-significant bits.
    """


@audio.command("encode")
@click.option("--input", "inp", required=True, help="Cover audio (WAV, FLAC, AIFF, or MP3)")
@click.option("--output", required=True, help="Output audio path (must be .wav, .flac, or .aiff)")
@click.option("--message", default=None, help="Text payload")
@click.option("--file", "payload_file", default=None, help="Binary payload file")
@click.option("--password", default=None, help="Encrypt payload with this password (AES-256-GCM)")
def audio_encode(inp, output, message, payload_file, password):
    from . import audio_stego
    payload = _get_payload(message, payload_file, password)
    audio_stego.encode(inp, payload, output)
    click.echo(f"Encoded {len(payload):,} bytes into {output}")


@audio.command("decode")
@click.option("--input", "inp", required=True, help="Stego audio file")
@click.option("--password", default=None, help="Decryption password")
@click.option("--output", default=None, help="Write decoded payload to file")
def audio_decode(inp, password, output):
    from . import audio_stego
    payload = audio_stego.decode(inp)
    _output_payload(payload, password, output)


# ---------------------------------------------------------------------------
# qr
# ---------------------------------------------------------------------------

@cli.group()
def qr():
    """QR code steganography (LSB in QR PNG, ECC-resilient)."""


@qr.command("generate")
@click.option("--url", required=True, help="URL to encode in QR")
@click.option("--output", required=True, help="Output PNG path")
@click.option("--scale", default=10, show_default=True, help="Scale factor (pixels per module)")
def qr_generate(url, output, scale):
    from . import qr_stego
    qr_stego.generate_qr(url, output, scale)
    click.echo(f"QR code saved to {output}")


@qr.command("encode")
@click.option("--input", "inp", required=True, help="Cover QR image (PNG)")
@click.option("--output", required=True, help="Output stego QR path")
@click.option("--message", default=None)
@click.option("--file", "payload_file", default=None)
@click.option("--password", default=None)
def qr_encode(inp, output, message, payload_file, password):
    from . import qr_stego
    payload = _get_payload(message, payload_file, password)
    qr_stego.encode(inp, payload, output)
    click.echo(f"Encoded {len(payload):,} bytes into QR image {output}")


@qr.command("decode")
@click.option("--input", "inp", required=True, help="Stego QR image")
@click.option("--password", default=None)
@click.option("--output", default=None)
def qr_decode(inp, password, output):
    from . import qr_stego
    payload = qr_stego.decode(inp)
    _output_payload(payload, password, output)


# ---------------------------------------------------------------------------
# text (zero-width Unicode)
# ---------------------------------------------------------------------------

@cli.group()
def text():
    """Zero-width Unicode character steganography."""


@text.command("encode")
@click.option("--cover", required=True, help="Visible cover text")
@click.option("--message", default=None, help="Text payload to hide")
@click.option("--file", "payload_file", default=None, help="Binary payload file")
@click.option("--password", default=None, help="Encrypt payload (AES-256-GCM)")
@click.option("--output", default=None, help="Write stego text to file")
def text_encode(cover, message, payload_file, password, output):
    from . import text_stego
    payload = _get_payload(message, payload_file, password)
    stego = text_stego.encode(cover, payload)
    if output:
        from pathlib import Path
        Path(output).write_text(stego, encoding="utf-8")
        click.echo(f"Stego text written to {output}")
    else:
        click.echo(stego)


@text.command("decode")
@click.option("--input", "inp", required=True, help="File containing stego text")
@click.option("--password", default=None)
@click.option("--output", default=None)
def text_decode(inp, password, output):
    from pathlib import Path
    from . import text_stego
    content = Path(inp).read_text(encoding="utf-8")
    payload = text_stego.decode(content)
    _output_payload(payload, password, output)


# ---------------------------------------------------------------------------
# pdf
# ---------------------------------------------------------------------------

@cli.group()
def pdf():
    """PDF steganography (invisible text layer + metadata)."""


@pdf.command("encode")
@click.option("--input", "inp", default=None, help="Existing PDF (uses metadata channel)")
@click.option("--output", required=True, help="Output PDF path")
@click.option("--message", default=None)
@click.option("--file", "payload_file", default=None)
@click.option("--password", default=None)
@click.option("--visible-text", default="Report", show_default=True,
              help="Visible text in new PDF")
def pdf_encode(inp, output, message, payload_file, password, visible_text):
    from . import pdf_stego
    payload = _get_payload(message, payload_file, password)
    pdf_stego.encode(payload, output, input_pdf=inp, visible_text=visible_text)
    click.echo(f"Encoded {len(payload):,} bytes into {output}")


@pdf.command("decode")
@click.option("--input", "inp", required=True, help="Stego PDF path")
@click.option("--password", default=None)
@click.option("--output", default=None)
def pdf_decode(inp, password, output):
    from . import pdf_stego
    payload = pdf_stego.decode(inp)
    _output_payload(payload, password, output)


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------

@cli.group()
def git():
    """Git commit metadata steganography (timestamp / whitespace channels)."""


@git.command("encode")
@click.option("--repo", required=True, help="Path to git repository")
@click.option("--message", default=None)
@click.option("--file", "payload_file", default=None)
@click.option("--password", default=None)
@click.option("--channel", default="timestamp", show_default=True,
              type=click.Choice(["timestamp", "whitespace"]))
@click.option("--base-message", default="Update documentation", show_default=True)
def git_encode(repo, message, payload_file, password, channel, base_message):
    from . import git_stego
    payload = _get_payload(message, payload_file, password)
    n = git_stego.encode(repo, payload, channel=channel, base_message=base_message)
    click.echo(f"Created {n} commits encoding {len(payload):,} bytes via {channel} channel")


@git.command("decode")
@click.option("--repo", required=True, help="Path to git repository")
@click.option("--channel", default="timestamp", show_default=True,
              type=click.Choice(["timestamp", "whitespace"]))
@click.option("--password", default=None)
@click.option("--output", default=None)
@click.option("--num-commits", default=None, type=int,
              help="Limit commits scanned (auto-detected by default)")
def git_decode(repo, channel, password, output, num_commits):
    from . import git_stego
    payload = git_stego.decode(repo, channel=channel, num_commits=num_commits)
    _output_payload(payload, password, output)


# ---------------------------------------------------------------------------
# capacity
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--input", "inp", required=True, help="File to analyse")
def capacity(inp):
    """Show how many payload bytes the given file can carry."""
    from pathlib import Path
    suffix = Path(inp).suffix.lower()

    if suffix in {".png", ".bmp"}:
        from . import image_stego
        cap = image_stego.capacity(inp)
        click.echo(f"Image capacity : {cap:,} bytes ({cap / 1024:.1f} KB)")
    elif suffix in {".wav", ".flac", ".aiff", ".mp3"}:
        from . import audio_stego
        cap = audio_stego.capacity(inp)
        click.echo(f"Audio capacity : {cap:,} bytes ({cap / 1024:.1f} KB)")
    elif suffix == ".pdf":
        from . import pdf_stego
        click.echo(f"PDF capacity   : {pdf_stego.capacity(inp)}")
    else:
        click.echo(f"Capacity estimation not supported for '{suffix}'.")
        click.echo("Tip: QR and text steganography have no inherent capacity limit.")
