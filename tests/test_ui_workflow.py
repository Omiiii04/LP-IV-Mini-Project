import io
import json
import re

from extensions import db
from models import Activity, Case, DiskImage, LogAnalysis


def csrf(client):
    page = client.get("/cases/new").data.decode()
    return re.search(r'name="csrf_token" type="hidden" value="([^"]+)', page).group(1)


def create_case(client, title="Incident"):
    token = csrf(client)
    response = client.post("/cases", data={"title": title, "investigator": "Analyst", "csrf_token": token})
    assert response.status_code == 302
    return token


def test_shared_navigation_exposes_all_investigation_workflows(client):
    page = client.get("/").data.decode()
    for label in ("Dashboard", "Cases", "Evidence", "Log Analysis", "Disk Images", "Reports"):
        assert label in page


def test_evidence_index_lists_original_filename_and_integrity_status(client, app):
    token = create_case(client)
    with app.app_context():
        case_id = Case.query.one().id
    client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(b"proof"), "proof.txt"), "csrf_token": token},
        content_type="multipart/form-data",
    )
    client.get("/evidence/1/download")

    response = client.get("/evidence")

    assert response.status_code == 200
    assert b"proof.txt" in response.data
    # Bug 3: Downloaded must NOT mean Verified!
    assert b"Not yet verified" in response.data

    # In-place verification marks it as Verified
    client.post("/evidence/1/verify", headers={"X-CSRFToken": token})
    response_verified = client.get("/evidence")
    assert b"Verified" in response_verified.data


def test_case_workspace_renders_saved_log_events_and_disk_image_status(client, app):
    create_case(client)
    with app.app_context():
        case = Case.query.one()
        db.session.add(
            LogAnalysis(
                case_id=case.id,
                filename="auth.log",
                events_processed=2,
                flagged_patterns=1,
                findings_json=json.dumps(
                    {
                        "events": [{"line": 1, "text": "failed login", "severity": "ERROR"}],
                        "findings": [{"reason": "lead"}],
                    }
                ),
            )
        )
        db.session.add(
            DiskImage(
                case_id=case.id,
                filename="image.dd",
                source="hidden",
                sha256="a" * 64,
                analysis_status="hash_only",
                results_json=json.dumps({"message": "hash only"}),
            )
        )
        db.session.add(Activity(case_id=case.id, action_type="case_created", result="Case created"))
        db.session.commit()
        case_id = case.id

    page = client.get(f"/cases/{case_id}")

    assert b"failed login" in page.data
    assert b"Hash-only" in page.data
    assert b"Case created" in page.data


def test_disk_image_upload_requires_existing_case(client):
    token = csrf(client)

    response = client.post(
        "/disk-images",
        data={"case_id": "999", "file": (io.BytesIO(b"image"), "image.dd"), "csrf_token": token},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
