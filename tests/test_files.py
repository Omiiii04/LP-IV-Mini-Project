import io
import re
from pathlib import Path

import pytest

from services.file_analyzer import copy_evidence, format_bytes, metadata, preview_file


def test_metadata_and_safe_evidence_copy(tmp_path: Path):
    source = tmp_path / "source.txt"
    source.write_text("proof", encoding="utf-8")
    info = metadata(source)
    destination = tmp_path / "evidence" / "copied.txt"
    copied = copy_evidence(source, destination)
    assert info["sha256"] == copied["sha256"]
    assert destination.read_text(encoding="utf-8") == "proof"


def test_copy_rejects_paths_outside_source_root(tmp_path: Path):
    source = tmp_path / "source.txt"
    source.write_text("proof", encoding="utf-8")
    with pytest.raises(ValueError, match="authorized evidence root"):
        copy_evidence(source, tmp_path / "evidence" / ".." / ".." / "escape.txt")


def test_copy_evidence_error_branches(tmp_path: Path):
    source = tmp_path / "original.txt"
    source.write_text("content", encoding="utf-8")
    dest = tmp_path / "dest.txt"

    # Destination already exists
    dest.write_text("existing", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        copy_evidence(source, dest, authorized_root=tmp_path)

    # Destination is same as source
    with pytest.raises(ValueError, match="destination must differ"):
        copy_evidence(source, source, authorized_root=tmp_path)

    # Source is directory, not file
    dir_source = tmp_path / "somedir"
    dir_source.mkdir()
    with pytest.raises(ValueError, match="source must be a file"):
        copy_evidence(dir_source, tmp_path / "other.txt", authorized_root=tmp_path)


def test_preview_text_and_binary(tmp_path: Path):
    text_file = tmp_path / "sample.txt"
    text_file.write_text("Forensic investigator line 1\nLine 2 data\n", encoding="utf-8")
    preview = preview_file(text_file)
    assert preview["is_text"] is True
    assert "Forensic investigator" in preview["text_preview"]
    assert len(preview["hex_lines"]) > 0
    assert not preview["is_truncated"]

    # Binary file with non-printable bytes
    bin_file = tmp_path / "sample.bin"
    bin_file.write_bytes(bytes([0x00, 0xFF, 0xFE, 0x12, 0x01, 0x00, 0x80, 0x90] * 10))
    bin_preview = preview_file(bin_file)
    assert bin_preview["is_text"] is False
    assert len(bin_preview["hex_lines"]) > 0

    # Truncated preview
    large_file = tmp_path / "large_preview.txt"
    large_file.write_bytes(b"A" * 8192)
    trunc_preview = preview_file(large_file, max_bytes=1024)
    assert trunc_preview["is_truncated"] is True
    assert trunc_preview["preview_bytes"] == 1024
    assert trunc_preview["total_size"] == 8192


def test_preview_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        preview_file(Path("non_existent_file_path_12345.bin"))


def test_format_bytes():
    assert format_bytes(500) == "500 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1024 * 1024) == "1.0 MB"
    assert format_bytes(1024 * 1024 * 1024) == "1.0 GB"
    assert format_bytes(1024 * 1024 * 1024 * 1024) == "1.0 TB"
    assert format_bytes(1024 * 1024 * 1024 * 1024 * 1024) == "1.0 PB"


def _csrf(client):
    page = client.get("/cases/new").data.decode("utf-8")
    return re.search(r'name="csrf_token" type="hidden" value="([^"]+)', page).group(1)


def test_upload_extension_spoofing_detection(client, app):
    # Setup test case
    with app.app_context():
        from extensions import db
        from models import Case

        case = Case(title="Spoofing Test Case", investigator="Analyst", description="Test")
        db.session.add(case)
        db.session.commit()
        case_id = case.id

    token = _csrf(client)

    # 1. Attempt to upload a Windows PE .exe disguised as .txt (starts with MZ = 0x4D, 0x5A)
    exe_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00FakeEXEPayload"
    res = client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(exe_payload), "malware.txt"), "csrf_token": token},
        content_type="multipart/form-data",
        headers={"Accept": "application/json"},
    )
    assert res.status_code == 400
    assert "executable binary content disguised as text" in res.json["error"].lower()

    # 2. Attempt to upload a Linux ELF executable disguised as .log (starts with \x7fELF)
    elf_payload = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00FakeELFPayload"
    res_elf = client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(elf_payload), "rootkit.log"), "csrf_token": token},
        content_type="multipart/form-data",
        headers={"Accept": "application/json"},
    )
    assert res_elf.status_code == 400
    assert "executable binary content disguised as text" in res_elf.json["error"].lower()


def test_upload_path_traversal_filename_sanitized(client, app):
    with app.app_context():
        from extensions import db
        from models import Case

        case = Case(title="Traversal Test Case", investigator="Analyst", description="Test")
        db.session.add(case)
        db.session.commit()
        case_id = case.id

    token = _csrf(client)

    # Upload with directory traversal in filename
    safe_content = b"clean investigator notes line\n"
    res = client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(safe_content), "../../../../etc/passwd.txt"), "csrf_token": token},
        content_type="multipart/form-data",
    )
    # werkzeug secure_filename strips ../../../../ into etc_passwd.txt or passwd.txt
    assert res.status_code == 302
    with app.app_context():
        from models import Evidence

        ev = Evidence.query.filter_by(case_id=case_id).first()
        assert ".." not in ev.source
        assert not ev.source.startswith("/")
