import io
import re
import struct

from extensions import db
from models import Activity, Case, Evidence
from services.disk_image_analyzer import examine
from services.hashing import multi_hash_file
from services.log_analyzer import analyze_log
from services.report_generator import csv_bytes, pdf_bytes


def _csrf(client):
    page = client.get("/cases/new").data.decode()
    return re.search(r'name="csrf_token" type="hidden" value="([^"]+)', page).group(1)


def test_case_status_transitions(app, client):
    token = _csrf(client)
    client.post("/cases", data={"title": "Status Transition Case", "investigator": "Examiner", "csrf_token": token})

    with app.app_context():
        case = Case.query.one()
        assert case.status == "Open"
        case_id = case.id

    # Transition to Closed
    res_closed = client.post(f"/cases/{case_id}/status", data={"status": "Closed", "csrf_token": token})
    assert res_closed.status_code == 302

    with app.app_context():
        case = db.session.get(Case, case_id)
        assert case.status == "Closed"
        act = Activity.query.filter_by(action_type="case_status_updated").first()
        assert act is not None
        assert "Status changed from Open to Closed" in act.result

    # Reopen case
    res_open = client.post(f"/cases/{case_id}/status", data={"status": "Open", "csrf_token": token})
    assert res_open.status_code == 302

    with app.app_context():
        case = db.session.get(Case, case_id)
        assert case.status == "Open"


def test_in_place_evidence_verification(app, client):
    token = _csrf(client)
    client.post("/cases", data={"title": "Forensic In-Place", "investigator": "Examiner", "csrf_token": token})

    with app.app_context():
        case = Case.query.one()
        case_id = case.id

    client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(b"critical system log file"), "sys.log"), "csrf_token": token},
        content_type="multipart/form-data",
    )

    with app.app_context():
        item = Evidence.query.one()
        item_id = item.id

    # Test successful in-place verification
    res = client.post(f"/evidence/{item_id}/verify", headers={"X-CSRFToken": token})
    assert res.status_code == 200
    assert res.json["status"] == "verified"
    assert "Integrity confirmed" in res.json["message"]

    with app.app_context():
        assert Activity.query.filter_by(action_type="evidence_integrity_verified").count() == 1

    # Tamper with the evidence file
    with app.app_context():
        from pathlib import Path

        evidence_item = db.session.get(Evidence, item_id)
        target = Path(evidence_item.source)
        if not target.is_absolute():
            target = Path(app.config["STORAGE_ROOT"]) / target
        with open(target, "wb") as f:
            f.write(b"tampered content")

    # Test failed in-place verification
    res_fail = client.post(f"/evidence/{item_id}/verify", headers={"X-CSRFToken": token})
    assert res_fail.status_code == 409
    assert res_fail.json["status"] == "failed"

    with app.app_context():
        assert Activity.query.filter_by(action_type="evidence_integrity_failure").count() == 1


def test_evidence_preview_endpoint(app, client):
    token = _csrf(client)
    client.post("/cases", data={"title": "Preview Case", "investigator": "Examiner", "csrf_token": token})

    with app.app_context():
        case = Case.query.one()
        case_id = case.id

    client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(b"Hello Forensic World! 1234567890"), "sample.txt"), "csrf_token": token},
        content_type="multipart/form-data",
    )

    with app.app_context():
        item_id = Evidence.query.one().id

    res = client.get(f"/evidence/{item_id}/preview")
    assert res.status_code == 200
    data = res.json
    assert data["filename"] == "sample.txt"
    assert data["is_text"] is True
    assert "Hello Forensic World!" in data["text_preview"]
    assert len(data["hex_lines"]) > 0
    assert data["hex_lines"][0]["offset"] == "00000000"


def test_multi_hash_generation(tmp_path):
    f = tmp_path / "hash_test.bin"
    f.write_bytes(b"forensic digital artifact test string")
    hashes = multi_hash_file(f)

    assert "md5" in hashes and len(hashes["md5"]) == 32
    assert "sha1" in hashes and len(hashes["sha1"]) == 40
    assert "sha256" in hashes and len(hashes["sha256"]) == 64


def test_native_mbr_partition_inspector(tmp_path):
    img = tmp_path / "disk.img"
    # Construct a synthetic 512-byte MBR sector with 0x55AA and one NTFS partition
    mbr_data = bytearray(512)
    # Boot signature at byte 510-511
    mbr_data[510:512] = b"\x55\xaa"
    # Partition entry 1 at offset 446 (0x1BE)
    # boot_flag=0x80 (active), start_chs=(0,1,1), part_type=0x07 (NTFS), end_chs=(0,1,1), start_lba=2048, num_sectors=65536
    part_entry = struct.pack("<BBBBBBBBII", 0x80, 0, 1, 1, 0x07, 0, 1, 1, 2048, 65536)
    mbr_data[446 : 446 + 16] = part_entry
    img.write_bytes(bytes(mbr_data))

    res = examine(img)
    assert res["scheme"] == "MBR (Master Boot Record)"
    assert len(res["partitions"]) == 1
    part = res["partitions"][0]
    assert part["bootable"] is True
    assert part["type_id"] == "0x07"
    assert "NTFS" in part["type_name"]
    assert part["start_lba"] == 2048
    assert part["num_sectors"] == 65536


def test_multipage_pdf_generation_and_unicode_safety(app):
    with app.app_context():
        case = Case(
            title="Rapport d'Enquête Française & 证据",
            investigator="Agent Müller",
            description="Complex Case with many items",
        )
        db.session.add(case)
        db.session.commit()
        case_id = case.id

        # Add 35 evidence items to trigger multiple pages
        for i in range(35):
            e = Evidence(
                case_id=case_id,
                description=f"pièce_jointe_{i:02d}.dat",
                source="mock_path",
                sha256="f" * 64,
                investigator="Agent Müller",
            )
            db.session.add(e)
            db.session.add(Activity(case_id=case_id, action_type="evidence_registered", result=f"Item {i}"))
        db.session.commit()

        pdf = pdf_bytes(case_id)
        assert pdf.startswith(b"%PDF")
        assert len(pdf) > 2000

        csv_out = csv_bytes(case_id)
        assert b"evidence" in csv_out


def test_expanded_log_security_patterns(tmp_path):
    log_file = tmp_path / "web_audit.log"
    log_file.write_text(
        """2026-10-01 12:00:00 INFO GET /index.html 200 - user information requested
2026-10-01 12:00:01 WARNING GET /download?file=../../etc/passwd 403
2026-10-01 12:00:02 CRITICAL GET /login?user=admin' OR '1'='1 500
2026-10-01 12:00:03 ERROR failed login user=root
2026-10-01 12:00:04 ERROR failed login user=root
""",
        encoding="utf-8",
    )
    res = analyze_log(log_file)
    assert res["events_processed"] == 5
    # Word boundary check: line 1 "user information" should NOT be classified as INFO just because of "infor",
    # but line 1 has "INFO" token so it is INFO.
    assert res["severity_counts"]["INFO"] == 1
    assert res["severity_counts"]["WARNING"] == 1
    assert res["severity_counts"]["CRITICAL"] == 1
    assert res["severity_counts"]["ERROR"] == 2

    # Should detect 3 distinct pattern leads: directory traversal, SQL injection, and repeated failed logins!
    reasons = [f["reason"] for f in res["findings"]]
    assert any("Directory traversal" in r for r in reasons)
    assert any("SQL" in r for r in reasons)
    assert any("failed login" in r for r in reasons)


def test_same_named_files_get_independent_statuses(app, client):
    token = _csrf(client)
    client.post("/cases", data={"title": "Multi Evidence Same Name", "investigator": "Examiner", "csrf_token": token})

    with app.app_context():
        case = Case.query.one()
        case_id = case.id

    # Upload two distinct files with the exact same filename
    client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(b"content of file one"), "same_name.log"), "csrf_token": token},
        content_type="multipart/form-data",
    )
    client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(b"content of file two"), "same_name.log"), "csrf_token": token},
        content_type="multipart/form-data",
    )

    with app.app_context():
        items = Evidence.query.filter_by(case_id=case_id).order_by(Evidence.id.asc()).all()
        assert len(items) == 2
        id1, id2 = items[0].id, items[1].id
        assert items[0].last_verified_ok is None
        assert items[1].last_verified_ok is None

    # Verify ONLY item 1
    res1 = client.post(f"/evidence/{id1}/verify", headers={"X-CSRFToken": token})
    assert res1.status_code == 200

    with app.app_context():
        i1 = db.session.get(Evidence, id1)
        i2 = db.session.get(Evidence, id2)
        assert i1.last_verified_ok is True
        assert i1.last_verified_at is not None
        # Item 2 must remain UNVERIFIED even though it has the exact same filename
        assert i2.last_verified_ok is None
        assert i2.last_verified_at is None

    # Tamper ONLY item 2 on disk
    with app.app_context():
        from pathlib import Path

        i2 = db.session.get(Evidence, id2)
        target = Path(i2.source)
        if not target.is_absolute():
            target = Path(app.config["STORAGE_ROOT"]) / target
        with open(target, "wb") as f:
            f.write(b"tampered content for file 2")

    # Verify item 2 -> fails
    res2 = client.post(f"/evidence/{id2}/verify", headers={"X-CSRFToken": token})
    assert res2.status_code == 409

    with app.app_context():
        i1 = db.session.get(Evidence, id1)
        i2 = db.session.get(Evidence, id2)
        assert i1.last_verified_ok is True
        assert i2.last_verified_ok is False


def test_download_does_not_mean_verified(app, client):
    token = _csrf(client)
    client.post("/cases", data={"title": "Download Status Case", "investigator": "Examiner", "csrf_token": token})

    with app.app_context():
        case = Case.query.one()
        case_id = case.id

    client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(b"pristine content"), "download_test.txt"), "csrf_token": token},
        content_type="multipart/form-data",
    )

    with app.app_context():
        item = Evidence.query.one()
        item_id = item.id
        assert item.last_verified_ok is None

    # Download the file
    dl_res = client.get(f"/evidence/{item_id}/download")
    assert dl_res.status_code == 200

    # Verification status must NOT be set to Verified just because it was downloaded
    with app.app_context():
        item = db.session.get(Evidence, item_id)
        assert item.last_verified_ok is None
