import shutil
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from app import create_app
from services.seed import seed_demo_data


@pytest.fixture(scope="module")
def smoke_server(tmp_path_factory):
    """Spins up a lightweight ephemeral live server for Playwright smoke tests."""
    tmp_path = tmp_path_factory.mktemp("playwright_server")
    storage_path = tmp_path / "storage"
    storage_path.mkdir(parents=True, exist_ok=True)

    app = create_app(
        {
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SECRET_KEY": "smoke-test-secret-key-123",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'smoke.db'}",
            "STORAGE_ROOT": str(storage_path),
        }
    )

    with app.app_context():
        seed_demo_data(app, reset=True)

    server = make_server("127.0.0.1", 0, app)
    port = server.port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_playwright_smoke_and_screenshots(smoke_server, tmp_path):
    from playwright.sync_api import sync_playwright

    screenshots_dir = Path("instance") / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir = Path(r"C:\Users\Admin\.gemini\antigravity-ide\brain\d657c5ec-e103-4ef5-81af-52f29b03baa5")

    with sync_playwright() as p:
        # Prefer pre-installed msedge or chromium
        browser = None
        for channel in ("msedge", "chrome", None):
            try:
                if channel:
                    browser = p.chromium.launch(channel=channel, headless=True)
                else:
                    browser = p.chromium.launch(headless=True)
                if browser:
                    break
            except Exception:
                continue

        assert browser is not None, "Failed to launch Playwright browser"

        context = browser.new_context(viewport={"width": 1280, "height": 900})
        page = context.new_page()

        # 1. Home Dashboard
        page.goto(f"{smoke_server}/", wait_until="networkidle")
        assert "Dashboard" in page.title() or "Forensic" in page.title()
        assert page.locator("h1").inner_text() == "Forensic Work Queue"

        dash_path = screenshots_dir / "01_home_dashboard.png"
        page.screenshot(path=str(dash_path), full_page=True)
        if artifact_dir.exists():
            shutil.copy2(dash_path, artifact_dir / "01_home_dashboard.png")

        # 2. Case Workspace Page
        page.click("text=Operation Chimera")
        page.wait_for_load_state("networkidle")
        assert "Operation Chimera" in page.locator(".page-title").inner_text()

        case_path = screenshots_dir / "02_case_workspace.png"
        page.screenshot(path=str(case_path), full_page=True)
        if artifact_dir.exists():
            shutil.copy2(case_path, artifact_dir / "02_case_workspace.png")

        # 3. Artifact Hex & Text Preview Modal
        # Click on the first "Inspect" button in the evidence table
        inspect_btn = page.locator("button:has-text('Inspect')").first
        assert inspect_btn.is_visible()
        inspect_btn.click()

        # Wait for modal overlay to gain the 'open' class
        page.wait_for_selector(".modal-overlay.open", state="visible", timeout=5000)
        assert page.locator("#artifactPreviewModal").is_visible()

        # Switch tabs to text view
        page.click("[data-preview-tab='text']")
        page.wait_for_timeout(300)

        modal_path = screenshots_dir / "03_evidence_preview_modal.png"
        page.screenshot(path=str(modal_path))
        if artifact_dir.exists():
            shutil.copy2(modal_path, artifact_dir / "03_evidence_preview_modal.png")

        # Close modal
        page.click("[data-close-modal]")
        page.wait_for_selector(".modal-overlay.open", state="hidden", timeout=5000)

        browser.close()
