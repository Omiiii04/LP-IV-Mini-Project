import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Load local .env if present (without external dependencies)
_env_path = BASE_DIR / ".env"
if _env_path.exists():
    for _line in _env_path.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip().strip("'\""))


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///dft.sqlite3")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Upload limits (configurable per route type)
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(66 * 1024 * 1024)))
    MAX_EVIDENCE_CONTENT_LENGTH = int(os.getenv("MAX_EVIDENCE_CONTENT_LENGTH", str(64 * 1024 * 1024)))  # 64 MB
    MAX_LOG_CONTENT_LENGTH = int(os.getenv("MAX_LOG_CONTENT_LENGTH", str(32 * 1024 * 1024)))  # 32 MB

    STORAGE_ROOT = os.getenv("STORAGE_ROOT", str(Path("instance") / "storage"))
    ALLOWED_EVIDENCE_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".pdf", ".zip", ".doc", ".docx"}
    ALLOWED_LOG_EXTENSIONS = {".log", ".txt", ".csv"}
    AUTO_SEED_DEMO = os.getenv("AUTO_SEED_DEMO", "false").lower() == "true"
