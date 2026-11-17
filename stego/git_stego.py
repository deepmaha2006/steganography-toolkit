"""
Git commit steganography — two encoding channels.

Channel A — timestamp seconds field
  Each commit timestamp is set so that (seconds % 64) encodes 6 bits of the
  payload.  Encode creates a sequence of empty commits whose timestamps carry
  the bits.  Decode scans the most recent N commits and reads the bits back.

Channel B — commit message whitespace
  Bits are encoded as trailing spaces on the first line of the commit message:
  an odd number of trailing spaces = bit 1; even = bit 0.

The two channels can be used independently; encode() defaults to Channel A.

Requirements
------------
  pip install gitpython
  A git repository must already exist at *repo_path*.
"""

import struct
import time
from datetime import timezone, datetime
from pathlib import Path


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
# Channel A — timestamp encoding
# ---------------------------------------------------------------------------

def encode_timestamp(repo_path: str | Path, payload: bytes,
                     base_message: str = "Update documentation") -> int:
    """
    Create commits in *repo_path* whose timestamps encode *payload*.

    Returns the number of commits created.
    """
    import git

    repo = git.Repo(str(repo_path))
    bits = list(_bits_from_bytes(struct.pack(">I", len(payload)))) + list(_bits_from_bytes(payload))

    # Pack 6 bits per commit using seconds % 64
    chunks = [bits[i:i + 6] for i in range(0, len(bits), 6)]
    commits_created = 0
    base_time = int(time.time())

    for i, chunk in enumerate(chunks):
        while len(chunk) < 6:
            chunk.append(0)
        value = int("".join(map(str, chunk)), 2)  # 0-63

        # Build timestamp: seconds field encodes the 6-bit value
        ts = base_time - (len(chunks) - i) * 100
        # Round down and add value
        ts = (ts // 64) * 64 + value
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        iso = dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")

        env = {
            "GIT_AUTHOR_DATE": iso,
            "GIT_COMMITTER_DATE": iso,
        }
        # Create an empty commit (no staged changes needed)
        repo.git.commit(
            "--allow-empty",
            "-m", f"{base_message} [{i}]",
            env=env,
        )
        commits_created += 1

    return commits_created


def decode_timestamp(repo_path: str | Path, num_commits: int | None = None) -> bytes:
    """
    Read payload encoded by encode_timestamp() from recent commits.

    *num_commits* defaults to auto-detection (reads until 32-bit header is
    satisfied and then reads the declared payload length).
    """
    import git

    repo = git.Repo(str(repo_path))

    # We need at least ceil((32 + length*8) / 6) commits; start with 10 for the header
    commits = list(repo.iter_commits(max_count=num_commits or 10000))
    commits.reverse()  # oldest first

    bits: list[int] = []
    for commit in commits:
        ts = commit.authored_date
        value = ts % 64
        for shift in range(5, -1, -1):
            bits.append((value >> shift) & 1)

        if len(bits) >= 32:
            length = struct.unpack(">I", _bytes_from_bits(bits[:32]))[0]
            if length > 0 and len(bits) >= 32 + length * 8:
                break

    if len(bits) < 32:
        raise ValueError("Not enough commits to read payload")

    length = struct.unpack(">I", _bytes_from_bits(bits[:32]))[0]
    if length == 0:
        raise ValueError("No payload detected (length = 0)")

    return _bytes_from_bits(bits[32: 32 + length * 8])


# ---------------------------------------------------------------------------
# Channel B — whitespace encoding
# ---------------------------------------------------------------------------

def encode_whitespace(repo_path: str | Path, payload: bytes,
                      base_message: str = "Fix typo") -> int:
    """
    Encode *payload* in commit messages using a hidden body marker.

    Each commit carries one bit encoded as a "STEGO:0" or "STEGO:1" line
    appended to the message body.  Git preserves multi-line message bodies
    verbatim, making this channel fully reliable.
    """
    import git

    repo = git.Repo(str(repo_path))
    bits = list(_bits_from_bytes(struct.pack(">I", len(payload)))) + list(_bits_from_bytes(payload))
    for i, bit in enumerate(bits):
        msg = f"{base_message} [{i}]\n\nSTEGO:{bit}"
        repo.git.commit("--allow-empty", "-m", msg)
    return len(bits)


def decode_whitespace(repo_path: str | Path, num_commits: int | None = None) -> bytes:
    """Extract payload hidden by encode_whitespace()."""
    import git

    repo = git.Repo(str(repo_path))
    commits = list(repo.iter_commits(max_count=num_commits or 10000))
    commits.reverse()

    bits: list[int] = []
    for commit in commits:
        msg = commit.message
        # Find the STEGO marker line
        for line in msg.splitlines():
            if line.startswith("STEGO:"):
                bits.append(int(line[6:].strip()))
                break
        else:
            continue  # skip non-stego commits

        if len(bits) >= 32:
            length = struct.unpack(">I", _bytes_from_bits(bits[:32]))[0]
            if length > 0 and len(bits) >= 32 + length * 8:
                break

    if len(bits) < 32:
        raise ValueError("Not enough commits to read payload")
    length = struct.unpack(">I", _bytes_from_bits(bits[:32]))[0]
    return _bytes_from_bits(bits[32: 32 + length * 8])


# ---------------------------------------------------------------------------
# Unified API
# ---------------------------------------------------------------------------

def encode(repo_path: str | Path, payload: bytes, channel: str = "timestamp",
           base_message: str = "Update documentation") -> int:
    if channel == "timestamp":
        return encode_timestamp(repo_path, payload, base_message)
    elif channel == "whitespace":
        return encode_whitespace(repo_path, payload, base_message)
    else:
        raise ValueError(f"Unknown channel '{channel}'; choose 'timestamp' or 'whitespace'")


def decode(repo_path: str | Path, channel: str = "timestamp",
           num_commits: int | None = None) -> bytes:
    if channel == "timestamp":
        return decode_timestamp(repo_path, num_commits)
    elif channel == "whitespace":
        return decode_whitespace(repo_path, num_commits)
    else:
        raise ValueError(f"Unknown channel '{channel}'")
