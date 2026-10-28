import re

from models import Activity, Case, Evidence, LogAnalysis
from services.seed import seed_demo_data


def test_seed_demo_data_populates_three_cases(app):
    with app.app_context():
        res = seed_demo_data(app, reset=True)
        assert len(res["cases"]) == 3
        case_statuses = {c["status"] for c in res["cases"]}
        assert case_statuses == {"Open", "In Progress", "Closed"}

        # Verify Case 1 (Operation Chimera)
        c1 = Case.query.filter_by(title="Operation Chimera - Corporate Data Exfiltration").one()
        assert c1.status == "Open"
        assert len(c1.evidence) >= 2
        assert len(c1.log_analyses) >= 2
        assert len(c1.disk_images) >= 1
        assert len(c1.reports) >= 3

        # Verify deliberately tampered file
        tampered_ev = Evidence.query.get(res["tampered_evidence_id"])
        assert tampered_ev is not None
        assert tampered_ev.description == "perimeter_network_triage.csv"
        assert tampered_ev.last_verified_ok is False
        assert tampered_ev.status_label == "Integrity failure"

        # Verify Case 2 (Incident 2026-088)
        c2 = Case.query.filter_by(title="Incident 2026-088 - Staging Gateway Infiltration").one()
        assert c2.status == "In Progress"
        assert len(c2.evidence) >= 1
        assert len(c2.disk_images) >= 1
        clean_log = LogAnalysis.query.filter_by(case_id=c2.id).first()
        assert clean_log is not None
        assert clean_log.flagged_patterns == 0

        # Verify Case 3 (Audit 2026-Q3)
        c3 = Case.query.filter_by(title="Audit 2026-Q3 - Workstation Decommission Verification").one()
        assert c3.status == "Closed"
        assert len(c3.evidence) >= 1
        assert len(c3.reports) >= 1

        # Check activity timeline
        activities = Activity.query.filter_by(case_id=c1.id).all()
        action_types = {a.action_type for a in activities}
        assert "case_created" in action_types
        assert "evidence_registered" in action_types
        assert "evidence_integrity_failure" in action_types
        assert "log_analyzed" in action_types
        assert "report_generated" in action_types


def test_seed_demo_idempotence_without_reset(app):
    with app.app_context():
        res1 = seed_demo_data(app, reset=True)
        assert len(res1["cases"]) == 3
        # Calling without reset when already seeded returns message without duplicating
        res2 = seed_demo_data(app, reset=False)
        assert "already loaded" in res2["message"]
        cases = Case.query.filter(Case.title.like("%Chimera%")).all()
        assert len(cases) == 1


def test_seed_demo_route_ui_trigger(client, app):
    page = client.get("/cases/new").data.decode("utf-8")
    token = re.search(r'name="csrf_token" type="hidden" value="([^"]+)', page).group(1)
    res = client.post("/seed-demo", data={"csrf_token": token}, follow_redirects=True)
    assert res.status_code == 200
    with app.app_context():
        assert Case.query.count() >= 3
