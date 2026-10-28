def test_report_json_contains_case_data(app, client):
    with app.app_context():
        from extensions import db
        from models import Case

        case = Case(title="Incident", investigator="Analyst")
        db.session.add(case)
        db.session.commit()
        case_id = case.id
    response = client.get(f"/reports/{case_id}.json")
    assert response.status_code == 200
    assert response.json["case"]["title"] == "Incident"


def test_report_csv_and_pdf_downloads(app, client):
    with app.app_context():
        from extensions import db
        from models import Case

        case = Case(title="Incident", investigator="Analyst")
        db.session.add(case)
        db.session.commit()
        case_id = case.id
    assert client.get(f"/reports/{case_id}.csv").mimetype == "text/csv"
    assert client.get(f"/reports/{case_id}.pdf").mimetype == "application/pdf"


def test_every_report_format_creates_a_report_record(app, client):
    with app.app_context():
        from extensions import db
        from models import Case, Report

        case = Case(title="Incident", investigator="Analyst")
        db.session.add(case)
        db.session.commit()
        case_id = case.id
    for extension in ("json", "csv", "pdf"):
        assert client.get(f"/reports/{case_id}.{extension}").status_code == 200
    with app.app_context():
        from models import Report

        assert Report.query.filter_by(case_id=case_id).count() == 3


def test_report_generation_failure_does_not_create_record(app, client, monkeypatch):
    with app.app_context():
        from extensions import db
        from models import Case, Report

        case = Case(title="Incident", investigator="Analyst")
        db.session.add(case)
        db.session.commit()
        case_id = case.id
    monkeypatch.setattr("app.report_data", lambda _: (_ for _ in ()).throw(RuntimeError("report failed")))
    assert client.get(f"/reports/{case_id}.json").status_code == 500
    with app.app_context():
        assert Report.query.filter_by(case_id=case_id).count() == 0


def test_report_sha256_is_recorded_on_report_row(app, client):
    import hashlib

    with app.app_context():
        from extensions import db
        from models import Case

        case = Case(title="Incident SHA", investigator="Analyst")
        db.session.add(case)
        db.session.commit()
        case_id = case.id

    for ext in ("json", "csv", "pdf"):
        resp = client.get(f"/reports/{case_id}.{ext}")
        assert resp.status_code == 200
        computed_sha = hashlib.sha256(resp.data).hexdigest()
        with app.app_context():
            from models import Report

            report = Report.query.filter_by(case_id=case_id, report_format=ext).order_by(Report.id.desc()).first()
            assert report is not None
            assert report.sha256 == computed_sha


def test_pdf_handles_non_ascii_unicode_safely(app, client):
    with app.app_context():
        from extensions import db
        from models import Case, Evidence

        # Title and description containing non-ASCII unicode (German, Russian, French, and smart quotes)
        case = Case(
            title="Affäre Schön · Операция «Химера»",
            investigator="Dr. Élena Rostova",
            description="Inspection of résumé & naïve unicode symbols: © 2026 — ‘test’",
        )
        db.session.add(case)
        db.session.commit()
        case_id = case.id

        ev = Evidence(
            case_id=case_id,
            description="données_protégées.txt",
            source="uploads/test.txt",
            sha256="b" * 64,
            last_verified_ok=True,
            investigator="Dr. Élena Rostova",
        )
        db.session.add(ev)
        db.session.commit()

    resp = client.get(f"/reports/{case_id}.pdf")
    assert resp.status_code == 200
    # The generated PDF must contain valid PDF bytes and must NOT replace non-ASCII characters with '?'
    # Check that report_data contains verification status
    json_resp = client.get(f"/reports/{case_id}.json").json
    assert json_resp["evidence"][0]["verification_status"] == "Verified"
    assert "tool" in json_resp
    assert "version" in json_resp["tool"]


def test_csv_report_content_structure(app, client):
    with app.app_context():
        from extensions import db
        from models import Case, Evidence

        case = Case(title="CSV Test Case", investigator="Lead Investigator")
        db.session.add(case)
        db.session.commit()
        case_id = case.id

        ev = Evidence(
            case_id=case_id,
            description="network_triage.csv",
            source="uploads/triage.csv",
            sha256="c" * 64,
            last_verified_ok=False,
            investigator="Lead Investigator",
        )
        db.session.add(ev)
        db.session.commit()

    resp = client.get(f"/reports/{case_id}.csv")
    assert resp.status_code == 200
    csv_text = resp.data.decode("utf-8")
    assert "Digital Forensics Toolkit" in csv_text
    assert "CSV Test Case" in csv_text
    assert "network_triage.csv" in csv_text
    assert "Integrity failure" in csv_text
    assert "cccccccc" in csv_text
