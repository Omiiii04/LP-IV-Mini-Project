import io
import re
from pathlib import Path

from models import Activity, Case, Evidence, Report


def get_csrf(client):
    page = client.get("/cases/new").data.decode("utf-8")
    match = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', page)
    assert match, "CSRF token not found in page"
    return match.group(1)


def test_full_investigative_lifecycle(client, app, sample_data):
    token = get_csrf(client)

    # 1. Create Case
    res = client.post(
        "/cases",
        data={
            "title": "Operation Wintermute - Full Audit Lifecycle",
            "investigator": "Forensic Lead J. Case",
            "description": "Comprehensive integration audit from ingestion to reporting.",
            "csrf_token": token,
        },
        follow_redirects=True,
    )
    assert res.status_code == 200
    with app.app_context():
        case = Case.query.filter_by(title="Operation Wintermute - Full Audit Lifecycle").one()
        case_id = case.id

    # 2. Upload Evidence File
    evidence_content = b"CRITICAL FORENSIC EVIDENCE: TRANSACTION RECORD 2026-X\n"
    res_ev = client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(evidence_content), "transaction_ledger.txt"), "csrf_token": token},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert res_ev.status_code == 200

    with app.app_context():
        ev = Evidence.query.filter_by(case_id=case_id).first()
        assert ev is not None
        assert ev.last_verified_ok is None  # Initially unverified
        ev_id = ev.id
        ev_source = ev.source

    # 3. In-place Verify (Intact)
    res_v = client.post(f"/evidence/{ev_id}/verify", headers={"X-CSRFToken": token})
    assert res_v.status_code == 200
    assert res_v.json["status"] == "verified"
    with app.app_context():
        ev_refreshed = Evidence.query.get(ev_id)
        assert ev_refreshed.last_verified_ok is True
        assert ev_refreshed.last_verified_at is not None

    # 4. Deliberately Tamper with Evidence on Disk
    storage_root = Path(app.config["STORAGE_ROOT"]).resolve()
    disk_file = storage_root / ev_source
    assert disk_file.exists()
    disk_file.write_bytes(b"MALICIOUS_TAMPERED_BYTES_OVERWRITTEN_BY_ATTACKER")

    # 5. Intercept on Download (HTTP 409 Conflict)
    res_dl = client.get(f"/evidence/{ev_id}/download")
    assert res_dl.status_code == 409
    assert "Integrity violation" in res_dl.data.decode("utf-8") or "mismatch" in res_dl.data.decode("utf-8")

    # 6. Intercept on In-place Verify (HTTP 409 Conflict)
    res_v_fail = client.post(f"/evidence/{ev_id}/verify", headers={"X-CSRFToken": token})
    assert res_v_fail.status_code == 409
    assert res_v_fail.json["status"] == "failed"
    with app.app_context():
        ev_tampered = Evidence.query.get(ev_id)
        assert ev_tampered.last_verified_ok is False
        # Activity audit entry logged
        act = Activity.query.filter_by(case_id=case_id, action_type="evidence_integrity_failure").first()
        assert act is not None

    # 7. Upload and Analyze Log File
    auth_log = sample_data / "auth.log"
    assert auth_log.exists()
    with open(auth_log, "rb") as f:
        res_log = client.post(
            f"/cases/{case_id}/logs",
            data={"file": (f, "auth.log"), "csrf_token": token},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
    assert res_log.status_code == 200

    # 8. Upload and Examine Disk Image
    mbr_img = sample_data / "mbr_fat.img"
    assert mbr_img.exists()
    with open(mbr_img, "rb") as f:
        res_img = client.post(
            "/disk-images",
            data={"case_id": str(case_id), "file": (f, "mbr_fat.img"), "csrf_token": token},
            content_type="multipart/form-data",
        )
    assert res_img.status_code == 200
    assert res_img.json["scheme"] == "MBR (Master Boot Record)"

    # 9. Generate and Assert Reports (JSON, CSV, PDF)
    res_json = client.get(f"/reports/{case_id}.json")
    assert res_json.status_code == 200
    assert res_json.json["case"]["title"] == "Operation Wintermute - Full Audit Lifecycle"
    assert res_json.json["evidence"][0]["verification_status"] == "Integrity failure"

    res_csv = client.get(f"/reports/{case_id}.csv")
    assert res_csv.status_code == 200
    assert b"Operation Wintermute" in res_csv.data

    res_pdf = client.get(f"/reports/{case_id}.pdf")
    assert res_pdf.status_code == 200
    assert res_pdf.data.startswith(b"%PDF")

    with app.app_context():
        reports = Report.query.filter_by(case_id=case_id).all()
        assert len(reports) == 3


def test_csrf_protection_on_all_post_routes(client, app):
    # Missing CSRF token must be rejected with 400 Bad Request
    res_case = client.post("/cases", data={"title": "Hacker Case", "investigator": "Attacker"})
    assert res_case.status_code == 400

    res_ev = client.post("/cases/1/evidence", data={"file": (io.BytesIO(b"data"), "test.txt")})
    assert res_ev.status_code == 400

    res_verify = client.post("/evidence/1/verify")
    assert res_verify.status_code == 400

    res_log = client.post("/cases/1/logs", data={"file": (io.BytesIO(b"log data"), "test.log")})
    assert res_log.status_code == 400

    res_disk = client.post("/disk-images", data={"case_id": "1", "file": (io.BytesIO(b"disk"), "disk.dd")})
    assert res_disk.status_code == 400


def test_error_handlers_content_negotiation(client):
    # HTML error by default
    res_html = client.get("/cases/999999")
    assert res_html.status_code == 404
    assert "text/html" in res_html.mimetype
    assert "404" in res_html.data.decode("utf-8")

    # JSON error when Accept: application/json
    res_json = client.get("/cases/999999", headers={"Accept": "application/json"})
    assert res_json.status_code == 404
    assert res_json.is_json
    assert res_json.json["status"] == 404
    assert "not found" in res_json.json["message"].lower()


def test_pagination_and_search_filters(client, app):
    token = get_csrf(client)
    with app.app_context():
        for i in range(15):
            client.post(
                "/cases",
                data={"title": f"Investigation Alpha {i}", "investigator": "Analyst", "csrf_token": token},
            )

    # Default pagination
    res = client.get("/cases")
    assert res.status_code == 200

    # Search filter matching Alpha 10
    res_search = client.get("/cases?q=Alpha 10")
    assert res_search.status_code == 200
    assert b"Alpha 10" in res_search.data

    # Search filter with zero matches
    res_empty = client.get("/cases?q=NonExistentKeywordXYZ")
    assert res_empty.status_code == 200
    assert b"No forensic cases" in res_empty.data or b"No cases found" in res_empty.data or b"0" in res_empty.data
