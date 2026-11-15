import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from app import create_app
from services.seed import seed_demo_data


def assert_no_horizontal_overflow(page):
    dimensions = page.evaluate(
        """() => ({
          viewport: window.innerWidth,
          document: document.documentElement.scrollWidth,
          body: document.body.scrollWidth,
          overflowing: [...document.body.querySelectorAll('*')]
            .filter(element => element.getBoundingClientRect().right > window.innerWidth + 1)
            .slice(0, 12)
            .map(element => `${element.tagName}.${element.className}`)
        })"""
    )
    assert dimensions["body"] <= dimensions["viewport"], dimensions


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

        # 1. Project overview and responsive layouts
        page.goto(f"{smoke_server}/", wait_until="networkidle")
        assert "Digital Forensics Toolkit" in page.title()
        assert page.locator("h1").inner_text() == "Collect carefully.\nKeep the record."
        assert page.locator("h1").is_visible()
        assert page.locator(".investigation-animation").get_attribute("role") == "img"
        assert page.locator(".flow-beam").is_visible()
        assert page.locator(".hero-copy").evaluate("element => Number.parseFloat(getComputedStyle(element).opacity) > 0")
        page.emulate_media(color_scheme="dark")
        assert page.locator("#hero-title").evaluate("element => getComputedStyle(element).color") == "rgb(27, 41, 36)"
        assert page.locator("#capabilities-title").evaluate(
            "element => getComputedStyle(element).color"
        ) == "rgb(27, 41, 36)"
        page.emulate_media(color_scheme="light")
        for width in (360, 768, 1280):
            page.set_viewport_size({"width": width, "height": 900})
            page.wait_for_timeout(100)
            assert_no_horizontal_overflow(page)
        landing_path = screenshots_dir / "00_project_overview.png"
        page.wait_for_timeout(700)
        page.screenshot(path=str(landing_path), full_page=True)
        page.set_viewport_size({"width": 360, "height": 800})
        page.wait_for_timeout(700)
        page.screenshot(path=str(screenshots_dir / "00_project_overview_mobile.png"), full_page=True)
        page.set_viewport_size({"width": 1280, "height": 900})
        page.emulate_media(reduced_motion="reduce")
        assert page.locator(".flow-beam").evaluate(
            "element => Number.parseFloat(getComputedStyle(element).animationDuration) < 0.001"
        )
        page.emulate_media(reduced_motion="no-preference")

        # 2. Workstation dashboard
        page.click("text=Open the workstation")
        page.wait_for_load_state("networkidle")
        assert page.locator("h1").inner_text() == "Forensic Work Queue"
        assert page.locator(".workspace-chrome").count() == 0
        for width in (360, 768, 1280):
            page.set_viewport_size({"width": width, "height": 900})
            page.wait_for_timeout(100)
            assert_no_horizontal_overflow(page)
            if width <= 640:
                mobile_nav = page.locator(".app-nav nav")
                assert mobile_nav.evaluate("element => getComputedStyle(element).position") == "fixed"
                assert float(mobile_nav.evaluate("element => getComputedStyle(element).borderRadius").replace("px", "")) >= 24
                mobile_nav_box = mobile_nav.bounding_box()
                assert mobile_nav_box["y"] > 900 - 120
                assert page.locator(".nav-item a").count() == 6
                assert page.locator(".nav-item a").evaluate_all(
                    "elements => elements.every(element => element.getBoundingClientRect().left >= document.querySelector('.app-nav nav').getBoundingClientRect().left && element.getBoundingClientRect().right <= document.querySelector('.app-nav nav').getBoundingClientRect().right)"
                )
            else:
                nav_box = page.locator(".app-nav").bounding_box()
                assert nav_box["y"] == 0
                assert nav_box["width"] >= width - 2
                assert page.locator(".nav-links").evaluate("element => getComputedStyle(element).flexDirection") == "row"
            assert page.locator(".nav-item a").evaluate_all(
                "elements => elements.every(element => element.getBoundingClientRect().right <= window.innerWidth + 1)"
            )
        page.set_viewport_size({"width": 360, "height": 800})
        page.screenshot(path=str(screenshots_dir / "01_workstation_mobile.png"), full_page=True)
        page.set_viewport_size({"width": 1280, "height": 900})

        assert page.locator("h1").inner_text() == "Forensic Work Queue"

        dash_path = screenshots_dir / "01_home_dashboard.png"
        page.screenshot(path=str(dash_path), full_page=True)

        # 2. Case Workspace Page
        page.click("text=Operation Chimera")
        page.wait_for_load_state("networkidle")
        assert "Operation Chimera" in page.locator(".page-title").inner_text()
        for width in (360, 768, 1280):
            page.set_viewport_size({"width": width, "height": 900})
            page.wait_for_timeout(100)
            assert_no_horizontal_overflow(page)
        page.set_viewport_size({"width": 1280, "height": 900})

        case_path = screenshots_dir / "02_case_workspace.png"
        page.screenshot(path=str(case_path), full_page=True)

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

        # Close modal
        page.click("[data-close-modal]")
        page.wait_for_selector(".modal-overlay.open", state="hidden", timeout=5000)

        browser.close()
