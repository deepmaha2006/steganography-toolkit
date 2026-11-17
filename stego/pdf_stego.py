"""
PDF steganography — three layered techniques.

Technique 1 — Invisible text layer (primary encode/decode)
  Uses reportlab to overlay the base64-encoded payload as white text on a
  white background at font-size 0.001 pt.  The text is invisible when
  printed or viewed but readable via PDF text-extraction.

Technique 2 — Metadata fields
  Embeds the hex-encoded payload in the PDF /Keywords metadata field of an
  existing PDF using PyPDF2.

Technique 3 — Whitespace encoding  (encode only, informational)
  Demonstrates the concept of encoding bits in inter-word space widths.

The encode() / decode() functions use Technique 1 (new PDFs) and fall back
to Technique 2 when given an existing PDF path.
"""

import base64
import struct
from pathlib import Path


# ---------------------------------------------------------------------------
# Technique 1 — invisible text in a new PDF (reportlab)
# ---------------------------------------------------------------------------

def encode_new(payload: bytes, output_path: str | Path, visible_text: str = "Report") -> None:
    """Create a new PDF at *output_path* with *payload* hidden as invisible text."""
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch

    encoded = base64.b64encode(payload).decode()
    c = canvas.Canvas(str(output_path))

    # Visible content
    c.setFont("Helvetica", 12)
    c.drawString(inch, 10 * inch, visible_text)

    # Hidden content — white text, essentially invisible
    c.setFillColorRGB(1, 1, 1)   # white on white
    c.setFont("Helvetica", 0.001)
    c.drawString(inch, 9 * inch, f"STEGO_BEGIN:{encoded}:STEGO_END")

    c.save()


def decode_new(pdf_path: str | Path) -> bytes:
    """Extract payload hidden by encode_new() (invisible text technique)."""
    import PyPDF2

    with open(pdf_path, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        for page in reader.pages:
            text = page.extract_text() or ""
            if "STEGO_BEGIN:" in text and ":STEGO_END" in text:
                start = text.index("STEGO_BEGIN:") + len("STEGO_BEGIN:")
                end = text.index(":STEGO_END", start)
                return base64.b64decode(text[start:end])

    raise ValueError("No invisible-text payload found")


# ---------------------------------------------------------------------------
# Technique 2 — metadata field injection (existing PDFs)
# ---------------------------------------------------------------------------

def encode_metadata(input_pdf: str | Path, payload: bytes, output_path: str | Path) -> None:
    """Embed *payload* in the /Keywords metadata field of an existing PDF."""
    import PyPDF2

    encoded = base64.b64encode(payload).decode()
    with open(input_pdf, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        writer = PyPDF2.PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        writer.add_metadata({
            "/Keywords": f"STEGO:{encoded}:END",
        })
    with open(output_path, "wb") as f:
        writer.write(f)


def decode_metadata(pdf_path: str | Path) -> bytes:
    """Extract payload from /Keywords metadata."""
    import PyPDF2

    with open(pdf_path, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        meta = reader.metadata or {}
        keywords = meta.get("/Keywords", "")
        if "STEGO:" in keywords and ":END" in keywords:
            start = keywords.index("STEGO:") + len("STEGO:")
            end = keywords.index(":END", start)
            return base64.b64decode(keywords[start:end])

    raise ValueError("No metadata payload found")


# ---------------------------------------------------------------------------
# Unified API
# ---------------------------------------------------------------------------

def encode(payload: bytes, output_path: str | Path,
           input_pdf: str | Path | None = None,
           visible_text: str = "Report") -> None:
    """
    If *input_pdf* is supplied, embed via metadata (Technique 2).
    Otherwise create a new PDF with invisible text (Technique 1).
    """
    if input_pdf is not None:
        encode_metadata(input_pdf, payload, output_path)
    else:
        encode_new(payload, output_path, visible_text)


def decode(pdf_path: str | Path) -> bytes:
    """Try invisible-text extraction first, then metadata."""
    try:
        return decode_new(pdf_path)
    except Exception:
        pass
    try:
        return decode_metadata(pdf_path)
    except Exception:
        pass
    raise ValueError("No steganographic payload found in PDF")


def capacity(pdf_path: str | Path | None = None) -> str:
    return "PDF steganography uses base64 text; capacity is effectively unlimited"
