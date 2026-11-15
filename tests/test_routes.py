def test_health_and_csrf(client):
    assert client.get("/health").json == {"status": "ok"}
    response = client.post("/cases", data={"title": "case"})
    assert response.status_code == 400


def test_case_creation_and_dashboard(client):
    token = client.get("/cases/new").data.decode()
    import re

    csrf = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', token).group(1)
    response = client.post("/cases", data={"title": "Laptop review", "investigator": "Analyst", "csrf_token": csrf})
    assert response.status_code == 302
    assert b"Laptop review" in client.get("/cases").data
    assert b"Laptop review" in client.get("/workspace").data


def test_new_case_form_posts_to_case_creation_route(client):
    response = client.get("/cases/new")

    assert b'action="/cases"' in response.data


def test_evidence_uploads_use_unique_storage_names_and_preserve_original(client, app):
    import io
    import re

    token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', client.get("/cases/new").data.decode()).group(
        1
    )
    client.post("/cases", data={"title": "Incident", "investigator": "Analyst", "csrf_token": token})
    with app.app_context():
        from models import Case

        case_id = Case.query.one().id
    for content in (b"one", b"two"):
        response = client.post(
            f"/cases/{case_id}/evidence",
            data={"file": (io.BytesIO(content), "same.txt"), "csrf_token": token},
            content_type="multipart/form-data",
        )
        assert response.status_code == 302
    with app.app_context():
        from models import Evidence

        items = Evidence.query.order_by(Evidence.id).all()
        assert [item.description for item in items] == ["same.txt", "same.txt"]
        assert len({item.source for item in items}) == 2


def test_evidence_download_uses_registered_record(client, app):
    import io
    import re

    token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', client.get("/cases/new").data.decode()).group(
        1
    )
    client.post("/cases", data={"title": "Incident", "investigator": "Analyst", "csrf_token": token})
    with app.app_context():
        from models import Case

        case_id = Case.query.one().id
    client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(b"proof"), "proof.txt"), "csrf_token": token},
        content_type="multipart/form-data",
    )
    with app.app_context():
        from models import Evidence

        evidence_id = Evidence.query.one().id
    response = client.get(f"/evidence/{evidence_id}/download")
    assert response.status_code == 200
    assert response.data == b"proof"
    assert "proof.txt" in response.headers["Content-Disposition"]
    assert client.get("/evidence/999/download").status_code == 404


def test_evidence_download_rejects_tampering_and_logs_failure(client, app):
    import io
    import re

    token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', client.get("/cases/new").data.decode()).group(
        1
    )
    client.post("/cases", data={"title": "Incident", "investigator": "Analyst", "csrf_token": token})
    with app.app_context():
        from models import Case, Evidence

        case_id = Case.query.one().id
    client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(b"proof"), "proof.txt"), "csrf_token": token},
        content_type="multipart/form-data",
    )
    with app.app_context():
        from pathlib import Path

        item = Evidence.query.one()
        target = Path(item.source)
        if not target.is_absolute():
            target = Path(app.config["STORAGE_ROOT"]) / target
        with open(target, "wb") as stream:
            stream.write(b"tampered")
        evidence_id = item.id
    response = client.get(f"/evidence/{evidence_id}/download")
    assert response.status_code == 409
    with app.app_context():
        from models import Activity

        assert Activity.query.filter_by(action_type="evidence_integrity_failure").count() == 1


def test_upload_database_failure_removes_new_file(client, app, monkeypatch):
    import io
    import re

    token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', client.get("/cases/new").data.decode()).group(
        1
    )
    client.post("/cases", data={"title": "Incident", "investigator": "Analyst", "csrf_token": token})
    with app.app_context():
        from extensions import db
        from models import Case

        case_id = Case.query.one().id

        def fail_commit():
            raise RuntimeError("database unavailable")

        monkeypatch.setattr(db.session, "commit", fail_commit)
    response = client.post(
        f"/cases/{case_id}/evidence",
        data={"file": (io.BytesIO(b"proof"), "proof.txt"), "csrf_token": token},
        content_type="multipart/form-data",
    )
    assert response.status_code == 500
    assert not [path for path in __import__("pathlib").Path(app.config["STORAGE_ROOT"]).rglob("*") if path.is_file()]


def test_evidence_upload_rejects_empty_and_disallowed_files(client, app):
    import io
    import re

    token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', client.get("/cases/new").data.decode()).group(
        1
    )
    client.post("/cases", data={"title": "Incident", "investigator": "Analyst", "csrf_token": token})
    with app.app_context():
        from models import Case

        case_id = Case.query.one().id
    for content, name in ((b"", "empty.txt"), (b"x", "secret.exe")):
        response = client.post(
            f"/cases/{case_id}/evidence",
            data={"file": (io.BytesIO(content), name), "csrf_token": token},
            content_type="multipart/form-data",
        )
        assert response.status_code == 400


def test_refuse_to_start_in_production_with_default_secret():
    import pytest

    from app import create_app

    with pytest.raises(RuntimeError, match="(?i)secret_key"):
        create_app(
            {
                "TESTING": False,
                "DEBUG": False,
                "SECRET_KEY": "change-me-in-production",
            }
        )
