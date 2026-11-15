def test_root_page_introduces_project_and_links_to_workstation(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"Collect carefully." in response.data
    assert b"CASEWORK SYSTEM" not in response.data
    assert b"/workspace" in response.data
    assert b"SHA-256" in response.data
    assert b"Log review" in response.data


def test_landing_page_shows_an_illustrative_evidence_workflow(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b'class="investigation-animation"' in response.data
    assert b"Illustrative animation" in response.data
    assert b"SHA-256 baseline" in response.data
    assert b"work-queue.png" not in response.data


def test_render_blueprint_uses_docker_and_persistent_case_storage():
    from pathlib import Path

    blueprint = (Path(__file__).resolve().parents[1] / "render.yaml").read_text(encoding="utf-8")

    assert "runtime: docker" in blueprint
    assert "mountPath: /var/data" in blueprint
    assert "sqlite:////var/data/dft.sqlite3" in blueprint


def test_legacy_project_video_artifacts_are_removed():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]

    assert not (root / "docs/project-overview.mp4").exists()
    assert not (root / "scripts/make_project_video.py").exists()


def test_workstation_is_available_at_workspace_route(client):
    response = client.get("/workspace")

    assert response.status_code == 200
    assert b"Forensic Work Queue" in response.data


def test_disk_image_workflow_is_removed_from_app(client):
    assert client.get("/disk-images").status_code == 404
    assert all(rule.rule != "/disk-images" for rule in client.application.url_map.iter_rules())
    assert b"Disk Images" not in client.get("/workspace").data


def test_render_showcase_mode_seeds_samples_when_database_is_empty(tmp_path):
    from app import create_app
    from models import Case, Evidence, LogAnalysis

    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'showcase.db'}",
            "STORAGE_ROOT": str(tmp_path / "showcase-storage"),
            "AUTO_SEED_DEMO": True,
        }
    )

    with app.app_context():
        assert Case.query.count() == 3
        assert Evidence.query.count() >= 4
        assert LogAnalysis.query.count() >= 3


def test_showcase_button_rebuilds_demo_records_without_removing_user_cases(client, app):
    import re

    from extensions import db
    from models import Activity, Case, Evidence, LogAnalysis, Report
    from services.seed import seed_demo_data

    with app.app_context():
        seed_demo_data(app, reset=True)
        db.session.add(Case(title="My case", investigator="Analyst"))
        Evidence.query.filter_by(description="notes.txt").delete()
        LogAnalysis.query.delete()
        Activity.query.filter_by(action_type="log_analyzed").delete()
        Report.query.delete()
        db.session.commit()

    page = client.get("/").data.decode("utf-8")
    token = re.search(r'name="csrf_token" value="([^"]+)', page).group(1)
    response = client.post("/seed-demo", data={"csrf_token": token}, follow_redirects=True)

    assert response.status_code == 200
    with app.app_context():
        assert Case.query.count() == 4
        assert Evidence.query.filter_by(description="notes.txt").count() == 1
        assert LogAnalysis.query.count() >= 3
        assert Report.query.count() >= 3
        assert Activity.query.filter_by(action_type="log_analyzed").count() >= 3
