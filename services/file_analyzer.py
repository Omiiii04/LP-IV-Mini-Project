import shutil
from pathlib import Path

from .hashing import multi_hash_file, sha256_file


def format_bytes(num_bytes: int) -> str:
    """Formats bytes into human-readable size."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}" if unit != "B" else f"{num_bytes} B"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def metadata(path: str | Path) -> dict:
    """Extracts forensic metadata and cryptographic hashes for a file."""
    path = Path(path)
    stat = path.stat()
    hashes = multi_hash_file(path)
    return {
        "name": path.name,
        "extension": path.suffix.lower(),
        "size": stat.st_size,
        "size_formatted": format_bytes(stat.st_size),
        "modified": stat.st_mtime,
        "sha256": hashes["sha256"],
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
    }


def copy_evidence(source: str | Path, destination: str | Path, authorized_root: str | Path | None = None) -> dict:
    """Safely copies an evidence file, verifying boundary constraints and SHA-256 integrity."""
    source = Path(source).resolve()
    destination = Path(destination).resolve()

    # Verify destination boundary
    root = Path(authorized_root).resolve() if authorized_root else source.parent
    try:
        destination.relative_to(root)
    except ValueError:
        raise ValueError("destination must remain inside the authorized evidence root")

    if not source.is_file() or destination == source:
        raise ValueError("source must be a file and destination must differ")

    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise ValueError("refusing to overwrite evidence")

    shutil.copy2(source, destination)
    result = metadata(destination)
    if result["sha256"] != sha256_file(source):
        destination.unlink(missing_ok=True)
        raise ValueError("hash mismatch after copy")
    return result


def preview_file(path: str | Path, max_bytes: int = 4096) -> dict:
    """Generates a forensic hex dump and text preview for a file up to max_bytes."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    size = path.stat().st_size
    with path.open("rb") as stream:
        raw = stream.read(max_bytes)

    # Build formatted hex dump (offset, hex bytes, ascii)
    hex_lines = []
    for i in range(0, len(raw), 16):
        chunk = raw[i : i + 16]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        # Pad hex display if chunk < 16 bytes
        if len(chunk) < 16:
            hex_bytes = hex_bytes.ljust(16 * 3 - 1)
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        offset = f"{i:08X}"
        hex_lines.append({"offset": offset, "hex": hex_bytes, "ascii": ascii_repr})

    # Try decoding text
    is_text = True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
            # If large proportion of non-printable chars, mark as binary
            non_printable = sum(1 for c in text if ord(c) < 32 and c not in "\r\n\t")
            if non_printable / max(1, len(text)) > 0.15:
                is_text = False
        except Exception:
            text = ""
            is_text = False

    return {
        "filename": path.name,
        "total_size": size,
        "preview_bytes": len(raw),
        "is_truncated": size > max_bytes,
        "is_text": is_text,
        "text_preview": text if is_text else "",
        "hex_lines": hex_lines,
    }
