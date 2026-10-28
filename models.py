from datetime import datetime, timezone

from extensions import db


def utcnow():
    """Returns timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    investigator = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    status = db.Column(db.String(30), default="Open", nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    evidence = db.relationship("Evidence", backref="case", lazy=True, cascade="all, delete-orphan")
    disk_images = db.relationship("DiskImage", backref="case", lazy=True, cascade="all, delete-orphan")
    activities = db.relationship("Activity", backref="case", lazy=True, cascade="all, delete-orphan")
    log_analyses = db.relationship("LogAnalysis", backref="case", lazy=True, cascade="all, delete-orphan")
    reports = db.relationship("Report", backref="case", lazy=True, cascade="all, delete-orphan")


class Evidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)
    description = db.Column(db.String(250), nullable=False)
    source = db.Column(db.Text, nullable=False)  # stored relative to STORAGE_ROOT
    sha256 = db.Column(db.String(64), nullable=False)
    collected_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    examined_at = db.Column(db.DateTime, nullable=True)
    last_verified_at = db.Column(db.DateTime, nullable=True)
    last_verified_ok = db.Column(db.Boolean, nullable=True)  # True = verified, False = failed, None = unverified
    investigator = db.Column(db.String(120), nullable=False)

    @property
    def status_label(self) -> str:
        if self.last_verified_ok is True:
            return "Verified"
        elif self.last_verified_ok is False:
            return "Integrity failure"
        return "Not yet verified"


class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)
    action_type = db.Column(db.String(80), nullable=False)
    result = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class LogAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)
    filename = db.Column(db.String(250), nullable=False)
    events_processed = db.Column(db.Integer, nullable=False)
    flagged_patterns = db.Column(db.Integer, nullable=False)
    findings_json = db.Column(db.Text, nullable=False)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)
    report_format = db.Column(db.String(20), default="json", nullable=False)
    sha256 = db.Column(db.String(64), nullable=True)
    generated_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class DiskImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=True)
    filename = db.Column(db.String(250), nullable=False)
    source = db.Column(db.Text, nullable=False)  # stored relative to STORAGE_ROOT
    sha256 = db.Column(db.String(64), nullable=False)
    analysis_status = db.Column(db.String(40), nullable=False)
    results_json = db.Column(db.Text, nullable=False, default="{}")
    warnings_json = db.Column(db.Text, nullable=False, default="[]")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
