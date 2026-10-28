import os
import tempfile
from pathlib import Path

import pytest

from app import create_app
from extensions import db


def pytest_configure(config):
    """Ensure pytest basetemp does not crash if OS temp has permission lockouts."""
    if not config.option.basetemp:
        try:
            username = os.getenv("USERNAME") or os.getenv("USER") or "user"
            probe = Path(tempfile.gettempdir()) / f"pytest-of-{username}"
            if probe.exists():
                list(os.scandir(str(probe)))
        except (PermissionError, OSError):
            safe_temp = Path(tempfile.gettempdir()) / f"pytest_dft_{os.getpid()}"
            config.option.basetemp = str(safe_temp)


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "WTF_CSRF_ENABLED": True,
            "SECRET_KEY": "test-secret",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
            "STORAGE_ROOT": str(tmp_path / "storage"),
            "MAX_CONTENT_LENGTH": 1024 * 1024,
        }
    )
    with application.app_context():
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def sample_data():
    return Path(__file__).resolve().parent.parent / "sample_data"
