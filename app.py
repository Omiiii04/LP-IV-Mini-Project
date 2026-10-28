import hashlib
import json
from pathlib import Path
from uuid import uuid4

import click
from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_wtf import FlaskForm
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.utils import secure_filename
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired

from config import Config
from extensions import csrf, db
from models import Activity, Case, DiskImage, Evidence, LogAnalysis, Report, utcnow
from services.disk_image_analyzer import examine
from services.file_analyzer import metadata, preview_file
from services.hashing import hashes_match
from services.log_analyzer import analyze_log
from services.report_generator import csv_bytes, pdf_bytes, report_data


class UploadError(Exception):
    """Centralized user-facing upload exception."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class CaseForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    investigator = StringField("Investigator", validators=[DataRequired()])
    description = TextAreaField("Description")


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    # Bug 8: Refuse to start in production/non-debug mode with default SECRET_KEY
    import sys

    is_seed_cli = any("seed" in arg for arg in sys.argv)
    if (
        not app.debug
        and not app.testing
        and not is_seed_cli
        and app.config.get("SECRET_KEY") in ("change-me-in-production", "", None)
    ):
        raise RuntimeError("Insecure configuration: refusing to start in non-debug mode with default SECRET_KEY")

    storage_root = Path(app.config["STORAGE_ROOT"]).resolve()
    storage_root.mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    with app.app_context():
        db.create_all()
        # Ensure schema migrations for existing SQLite databases (Bug 3 & Phase 1)
        try:
            from sqlalchemy import inspect, text

            inspector = inspect(db.engine)
            if "evidence" in inspector.get_table_names():
                evidence_cols = {col["name"] for col in inspector.get_columns("evidence")}
                with db.engine.begin() as conn:
                    if "last_verified_at" not in evidence_cols:
                        conn.execute(text("ALTER TABLE evidence ADD COLUMN last_verified_at DATETIME"))
                    if "last_verified_ok" not in evidence_cols:
                        conn.execute(text("ALTER TABLE evidence ADD COLUMN last_verified_ok BOOLEAN"))
                    if "examined_at" not in evidence_cols:
                        conn.execute(text("ALTER TABLE evidence ADD COLUMN examined_at DATETIME"))
            if "report" in inspector.get_table_names():
                report_cols = {col["name"] for col in inspector.get_columns("report")}
                with db.engine.begin() as conn:
                    if "report_format" not in report_cols:
                        conn.execute(text("ALTER TABLE report ADD COLUMN report_format VARCHAR(20) DEFAULT 'json'"))
                    if "sha256" not in report_cols:
                        conn.execute(text("ALTER TABLE report ADD COLUMN sha256 VARCHAR(64)"))
            if "disk_image" in inspector.get_table_names():
                disk_cols = {col["name"] for col in inspector.get_columns("disk_image")}
                with db.engine.begin() as conn:
                    if "warnings_json" not in disk_cols:
                        conn.execute(text("ALTER TABLE disk_image ADD COLUMN warnings_json TEXT DEFAULT '[]'"))
        except Exception:
            pass

    # --- Storage & Path Helpers (Bug 5: Never leak absolute server paths) ---
    def resolve_storage_path(stored_source: str) -> Path:
        target = (storage_root / stored_source).resolve()
        try:
            target.relative_to(storage_root)
        except ValueError:
            raise UploadError("Invalid storage path reference outside authorized root", 400)
        return target

    def upload_target(folder: str, original_name: str) -> tuple[str, Path]:
        suffix = Path(original_name).suffix.lower()
        rel_path = Path(folder) / f"{uuid4().hex}{suffix}"
        target = (storage_root / rel_path).resolve()
        target.relative_to(storage_root)
        # Return forward-slash relative path for cross-platform DB storage
        return str(rel_path).replace("\\", "/"), target

    def save_upload(uploaded, folder: str, allowed: set[str], max_size: int | None = None) -> tuple[str, str, Path]:
        """
        Stream upload to disk in chunks, enforce per-route max limits, check magic/extension,
        and return (filename, relative_source, target_path).
        """
        if not uploaded:
            raise UploadError("File is required", 400)
        filename = secure_filename(uploaded.filename or "")
        if not filename or Path(filename).suffix.lower() not in allowed:
            raise UploadError("Invalid or unsupported file type", 400)

        # Check declared Content-Length if present
        if max_size and request.content_length and request.content_length > max_size:
            raise UploadError(
                f"File payload too large: exceeds {max_size // (1024 * 1024)} MB limit for this category", 413
            )

        rel_path, target = upload_target(folder, filename)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            total_bytes = 0
            with target.open("wb") as dst:
                while True:
                    chunk = uploaded.stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if max_size and total_bytes > max_size:
                        raise UploadError(
                            f"File payload too large: exceeds {max_size // (1024 * 1024)} MB limit for this category",
                            413,
                        )
                    dst.write(chunk)

            if total_bytes == 0:
                raise UploadError("Empty uploads are not accepted", 400)

            # Detect extension spoofing via magic bytes (e.g. .exe/.elf renamed as .txt/.log/.csv/.json)
            with target.open("rb") as check_stream:
                magic_header = check_stream.read(16)
            ext = Path(filename).suffix.lower()
            if ext in {".txt", ".log", ".csv", ".json"} and (
                magic_header.startswith(b"MZ") or magic_header.startswith(b"\x7fELF")
            ):
                raise UploadError("File format mismatch: executable binary content disguised as text evidence", 400)

            return filename, rel_path, target
        except Exception:
            target.unlink(missing_ok=True)
            raise

    def record_report(case_id: int, report_format: str, content_bytes: bytes) -> str:
        """Records report entry in DB with computed SHA-256 digest."""
        sha = hashlib.sha256(content_bytes).hexdigest()
        report = Report(case_id=case_id, report_format=report_format, sha256=sha)
        db.session.add(report)
        db.session.commit()
        return sha

    # --- Error Handlers (Bug 2: Content negotiation HTML/JSON + friendly 413) ---
    def render_error_response(status_code: int, message: str):
        accept = request.headers.get("Accept", "")
        if "application/json" in accept or request.is_json:
            return jsonify({"error": message, "message": message, "status": status_code}), status_code
        template_name = f"{status_code}.html"
        return render_template(template_name, error_message=message), status_code

    @app.errorhandler(UploadError)
    def handle_upload_error(error):
        return render_error_response(error.status_code, error.message)

    @app.errorhandler(RequestEntityTooLarge)
    @app.errorhandler(413)
    def handle_413(error):
        msg = getattr(error, "description", None) or "Uploaded file exceeds maximum allowed capacity for this route."
        return render_error_response(413, msg)

    @app.errorhandler(400)
    def handle_400(error):
        msg = getattr(error, "description", None) or "Invalid request parameters."
        return render_error_response(400, msg)

    @app.errorhandler(404)
    def handle_404(error):
        msg = getattr(error, "description", None) or "Resource not found."
        return render_error_response(404, msg)

    @app.errorhandler(409)
    def handle_409(error):
        msg = getattr(error, "description", None) or "Cryptographic integrity conflict."
        return render_error_response(409, msg)

    @app.errorhandler(500)
    def handle_500(error):
        msg = "An unexpected error occurred during investigation processing."
        return render_error_response(500, msg)

    # --- Core Routes ---
    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/")
    def dashboard():
        from datetime import timedelta

        # Bug 7: Aggregate with SQL (func.sum), not Python loops
        total_flagged = db.session.query(db.func.coalesce(db.func.sum(LogAnalysis.flagged_patterns), 0)).scalar()

        # Work queue indicators
        pending_verification_count = Evidence.query.filter(Evidence.last_verified_ok.is_(None)).count()
        integrity_failure_count = Evidence.query.filter_by(last_verified_ok=False).count()

        idle_cutoff = utcnow() - timedelta(days=7)
        idle_cases_count = Case.query.filter(
            Case.status.in_(["Open", "In Progress"]), Case.created_at < idle_cutoff
        ).count()

        counts = {
            "cases": Case.query.count(),
            "evidence": Evidence.query.count(),
            "logs": LogAnalysis.query.count(),
            "flagged": int(total_flagged),
            "reports": Report.query.count(),
            "pending_verification": pending_verification_count,
            "integrity_failures": integrity_failure_count,
            "cases_idle": idle_cases_count,
        }

        # Work queue collections for dashboard triage
        queue_needs_verify = (
            Evidence.query.filter(Evidence.last_verified_ok.is_(None) | Evidence.last_verified_ok.is_(False))
            .order_by(Evidence.collected_at.desc())
            .limit(6)
            .all()
        )
        queue_flagged_logs = (
            LogAnalysis.query.filter(LogAnalysis.flagged_patterns > 0).order_by(LogAnalysis.id.desc()).limit(6).all()
        )
        idle_cases = (
            Case.query.filter(Case.status.in_(["Open", "In Progress"]), Case.created_at < idle_cutoff)
            .order_by(Case.created_at.asc())
            .limit(6)
            .all()
        )

        recent_activity = Activity.query.order_by(Activity.created_at.desc()).limit(10).all()
        recent_cases = Case.query.order_by(Case.created_at.desc()).limit(6).all()

        return render_template(
            "dashboard.html",
            counts=counts,
            cases=recent_cases,
            recent_activity=recent_activity,
            queue_needs_verify=queue_needs_verify,
            queue_flagged_logs=queue_flagged_logs,
            idle_cases=idle_cases,
        )

    @app.get("/cases")
    def cases():
        # Bug 7: Search and status filters + pagination
        page = request.args.get("page", 1, type=int)
        q = request.args.get("q", "").strip()
        status_filter = request.args.get("status", "").strip()

        query = Case.query
        if q:
            query = query.filter(Case.title.ilike(f"%{q}%") | Case.investigator.ilike(f"%{q}%"))
        if status_filter:
            query = query.filter_by(status=status_filter)

        pagination = query.order_by(Case.created_at.desc()).paginate(page=page, per_page=12, error_out=False)
        return render_template(
            "cases.html",
            pagination=pagination,
            cases=pagination.items,
            q=q,
            status_filter=status_filter,
        )

    @app.get("/evidence")
    def evidence_index():
        # Bug 3 & 7: Independent statuses stored on Evidence + pagination & filter
        page = request.args.get("page", 1, type=int)
        q = request.args.get("q", "").strip()
        status_filter = request.args.get("status", "").strip()

        query = Evidence.query
        if q:
            query = query.filter(Evidence.description.ilike(f"%{q}%"))
        if status_filter == "verified":
            query = query.filter(Evidence.last_verified_ok.is_(True))
        elif status_filter == "failed":
            query = query.filter(Evidence.last_verified_ok.is_(False))
        elif status_filter == "unverified":
            query = query.filter(Evidence.last_verified_ok.is_(None))

        pagination = query.order_by(Evidence.collected_at.desc()).paginate(page=page, per_page=15, error_out=False)

        # Build statuses dictionary for backwards-compatibility with templates/tests
        statuses = {}
        for item in pagination.items:
            if item.last_verified_ok is True:
                statuses[item.id] = "Verified on download"
            elif item.last_verified_ok is False:
                statuses[item.id] = "Integrity failure"
            else:
                statuses[item.id] = "Not yet verified"

        return render_template(
            "evidence.html",
            pagination=pagination,
            items=pagination.items,
            statuses=statuses,
            q=q,
            status_filter=status_filter,
        )

    @app.get("/logs")
    def logs_index():
        page = request.args.get("page", 1, type=int)
        q = request.args.get("q", "").strip()

        query = LogAnalysis.query
        if q:
            query = query.filter(LogAnalysis.filename.ilike(f"%{q}%"))

        pagination = query.order_by(LogAnalysis.id.desc()).paginate(page=page, per_page=15, error_out=False)
        return render_template("logs.html", pagination=pagination, analyses=pagination.items, q=q)

    @app.get("/disk-images")
    def disk_images_index():
        images = DiskImage.query.order_by(DiskImage.created_at.desc()).all()
        for img in images:
            try:
                img.results = json.loads(img.results_json)
            except Exception:
                img.results = {}
        return render_template(
            "disk_images.html",
            images=images,
            cases=Case.query.order_by(Case.title).all(),
            max_limit_mb=app.config["MAX_DISK_IMAGE_CONTENT_LENGTH"] // (1024 * 1024),
        )

    @app.get("/reports")
    def reports_index():
        return render_template("reports.html", cases=Case.query.order_by(Case.title).all())

    @app.get("/cases/new")
    def new_case():
        return render_template("case_form.html", form=CaseForm())

    @app.post("/cases")
    def create_case():
        form = CaseForm()
        if not form.validate_on_submit():
            return render_template("case_form.html", form=form), 400
        case = Case(
            title=form.title.data.strip(),
            investigator=form.investigator.data.strip(),
            description=form.description.data or "",
        )
        db.session.add(case)
        db.session.commit()
        db.session.add(Activity(case_id=case.id, action_type="case_created", result=case.title))
        db.session.commit()
        flash("Case created successfully.", "success")
        return redirect(url_for("cases"))

    @app.get("/cases/<int:case_id>")
    def case_detail(case_id):
        # Bug 7: db.get_or_404
        case = db.get_or_404(Case, case_id)
        analyses = LogAnalysis.query.filter_by(case_id=case.id).order_by(LogAnalysis.id.desc()).all()
        for analysis in analyses:
            try:
                analysis.findings = json.loads(analysis.findings_json)
            except Exception:
                analysis.findings = {}
        for img in case.disk_images:
            try:
                img.results = json.loads(img.results_json)
            except Exception:
                img.results = {}
        reports = Report.query.filter_by(case_id=case.id).order_by(Report.generated_at.desc()).all()
        activities = Activity.query.filter_by(case_id=case.id).order_by(Activity.created_at.desc()).all()
        return render_template(
            "case_detail.html",
            case=case,
            analyses=analyses,
            reports=reports,
            activities=activities,
            evidence_limit_mb=app.config["MAX_EVIDENCE_CONTENT_LENGTH"] // (1024 * 1024),
            log_limit_mb=app.config["MAX_LOG_CONTENT_LENGTH"] // (1024 * 1024),
            disk_limit_mb=app.config["MAX_DISK_IMAGE_CONTENT_LENGTH"] // (1024 * 1024),
        )

    @app.post("/cases/<int:case_id>/status")
    def update_case_status(case_id):
        case = db.get_or_404(Case, case_id)
        new_status = request.form.get("status", "").strip()
        allowed_statuses = ["Open", "In Progress", "Under Review", "Closed", "Archived"]
        if new_status in allowed_statuses:
            old_status = case.status
            case.status = new_status
            db.session.add(
                Activity(
                    case_id=case.id,
                    action_type="case_status_updated",
                    result=f"Status changed from {old_status} to {new_status}",
                )
            )
            db.session.commit()
            flash(f"Case #{case.id} status updated to {new_status}.", "success")
        return redirect(url_for("case_detail", case_id=case.id))

    @app.post("/cases/<int:case_id>/evidence")
    def add_evidence(case_id):
        case = db.get_or_404(Case, case_id)
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            abort(400, "file is required")

        try:
            filename, rel_path, target = save_upload(
                uploaded,
                "uploads",
                app.config["ALLOWED_EVIDENCE_EXTENSIONS"],
                max_size=app.config["MAX_EVIDENCE_CONTENT_LENGTH"],
            )
            info = metadata(target)
            db.session.add(
                Evidence(
                    case_id=case.id,
                    description=filename,
                    source=rel_path,  # Bug 5: relative path
                    sha256=info["sha256"],
                    investigator=case.investigator,
                    last_verified_ok=None,  # Not verified yet
                )
            )
            db.session.add(Activity(case_id=case.id, action_type="evidence_registered", result=filename))
            db.session.commit()
            flash(f"Evidence registered: {filename}", "success")
        except UploadError as ue:
            db.session.rollback()
            abort(ue.status_code, ue.message)
        except ValueError as error:
            db.session.rollback()
            abort(400, str(error))
        except HTTPException:
            db.session.rollback()
            raise
        except Exception:
            db.session.rollback()
            if "target" in locals() and isinstance(target, Path):
                target.unlink(missing_ok=True)
            abort(500, "evidence registration failed")
        return redirect(url_for("case_detail", case_id=case.id))

    @app.get("/evidence/<int:evidence_id>/download")
    def download_evidence(evidence_id):
        item = db.session.get(Evidence, evidence_id)
        if item is None:
            abort(404, "Evidence record not found")

        target = resolve_storage_path(item.source)
        if not target.is_file():
            abort(404, "Evidence file not found in storage")

        if not hashes_match(target, item.sha256):
            item.last_verified_at = utcnow()
            item.last_verified_ok = False
            db.session.add(
                Activity(case_id=item.case_id, action_type="evidence_integrity_failure", result=item.description)
            )
            db.session.commit()
            abort(409, "evidence integrity verification failed")

        # Bug 3: Downloaded must NOT mean Verified!
        db.session.add(Activity(case_id=item.case_id, action_type="evidence_downloaded", result=item.description))
        db.session.commit()
        return send_file(target, as_attachment=True, download_name=item.description)

    @app.post("/evidence/<int:evidence_id>/verify")
    def verify_evidence(evidence_id):
        """In-place cryptographic verification without downloading the entire file."""
        item = db.session.get(Evidence, evidence_id)
        if item is None:
            abort(404, "Evidence record not found")

        target = resolve_storage_path(item.source)
        if not target.is_file():
            abort(404, "Evidence file not found in storage")

        matched = hashes_match(target, item.sha256)
        item.last_verified_at = utcnow()
        item.last_verified_ok = matched

        if not matched:
            db.session.add(
                Activity(case_id=item.case_id, action_type="evidence_integrity_failure", result=item.description)
            )
            db.session.commit()
            return (
                jsonify(
                    {
                        "status": "failed",
                        "message": "Integrity violation: Current file digest does NOT match registered baseline!",
                        "sha256": item.sha256,
                    }
                ),
                409,
            )

        db.session.add(
            Activity(case_id=item.case_id, action_type="evidence_integrity_verified", result=item.description)
        )
        db.session.commit()
        return jsonify(
            {
                "status": "verified",
                "message": "Integrity confirmed: SHA-256 matches registered baseline.",
                "sha256": item.sha256,
            }
        )

    @app.get("/evidence/<int:evidence_id>/preview")
    def preview_evidence(evidence_id):
        """Generates hex and text preview of stored evidence file."""
        item = db.session.get(Evidence, evidence_id)
        if item is None:
            abort(404, "Evidence record not found")

        target = resolve_storage_path(item.source)
        if not target.is_file():
            abort(404, "Evidence file not found in storage")

        # Bug 3: Set examined_at
        item.examined_at = utcnow()
        db.session.commit()

        try:
            data = preview_file(target, max_bytes=8192)
            data["evidence_id"] = item.id
            data["filename"] = item.description
            data["description"] = item.description
            data["sha256"] = item.sha256
            return jsonify(data)
        except Exception as e:
            abort(500, f"Preview failed: {e}")

    @app.post("/cases/<int:case_id>/logs")
    def add_log(case_id):
        case = db.get_or_404(Case, case_id)
        uploaded = request.files.get("file")
        if not uploaded:
            abort(400, "file is required")

        try:
            filename, rel_path, target = save_upload(
                uploaded,
                "logs",
                app.config["ALLOWED_LOG_EXTENSIONS"],
                max_size=app.config["MAX_LOG_CONTENT_LENGTH"],
            )
        except UploadError as ue:
            abort(ue.status_code, ue.message)
        except ValueError as error:
            abort(400, str(error))

        result = analyze_log(target)

        # Bug 6: Cap stored event details and store findings, not full dumps, in Activity.result
        activity_summary = {
            "filename": filename,
            "events_processed": result["events_processed"],
            "flagged_patterns": result["flagged_patterns"],
            "findings_count": len(result["findings"]),
            "findings": [
                {"rule_id": f.get("rule_id"), "reason": f.get("reason"), "severity": f.get("severity")}
                for f in result["findings"]
            ],
        }

        db.session.add(
            LogAnalysis(
                case_id=case.id,
                filename=filename,
                events_processed=result["events_processed"],
                flagged_patterns=result["flagged_patterns"],
                findings_json=json.dumps(result),
            )
        )
        db.session.add(Activity(case_id=case.id, action_type="log_analysis", result=json.dumps(activity_summary)))
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            target.unlink(missing_ok=True)
            abort(500, "log registration failed")
        flash(f"Log analyzed: {filename}", "success")
        return redirect(url_for("case_detail", case_id=case.id))

    @app.get("/reports/<int:case_id>.json")
    def report_json(case_id):
        try:
            data = report_data(case_id)
        except HTTPException:
            raise
        except Exception:
            abort(500, "report generation failed")
        content_bytes = json.dumps(data, indent=2).encode("utf-8")
        record_report(case_id, "json", content_bytes)
        return Response(content_bytes, mimetype="application/json")

    @app.get("/reports/<int:case_id>.csv")
    def report_csv(case_id):
        try:
            content = csv_bytes(case_id)
        except HTTPException:
            raise
        except Exception:
            abort(500, "report generation failed")
        record_report(case_id, "csv", content)
        return Response(
            content,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=case-{case_id}.csv"},
        )

    @app.get("/reports/<int:case_id>.pdf")
    def report_pdf(case_id):
        try:
            content = pdf_bytes(case_id)
        except HTTPException:
            raise
        except Exception:
            abort(500, "report generation failed")
        record_report(case_id, "pdf", content)
        return Response(
            content,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=case-{case_id}.pdf"},
        )

    @app.post("/disk-images")
    def disk_image():
        # Bug 2: Return 400 on empty / invalid upload, never 500
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            abort(400, "Disk image file is required")

        case_id = request.form.get("case_id", type=int)
        if case_id is None or db.session.get(Case, case_id) is None:
            abort(400, "A valid case ID is required")

        try:
            filename, rel_path, target = save_upload(
                uploaded,
                "images",
                app.config["ALLOWED_DISK_IMAGE_EXTENSIONS"],
                max_size=app.config["MAX_DISK_IMAGE_CONTENT_LENGTH"],
            )
        except UploadError as ue:
            abort(ue.status_code, ue.message)
        except ValueError as error:
            abort(400, str(error))

        try:
            result = examine(target)
            item = DiskImage(
                case_id=case_id,
                filename=filename,
                source=rel_path,  # Bug 5: relative path
                sha256=result["sha256_before"],
                analysis_status="hash_only",
                results_json=json.dumps(result),
                warnings_json=json.dumps(result.get("warnings", [])),
            )
            db.session.add(item)
            db.session.add(Activity(case_id=case_id, action_type="disk_image_registered", result=filename))
            db.session.commit()

            is_form_submission = (
                request.form.get("format") == "html" or request.headers.get("Sec-Fetch-Dest") == "document"
            )
            if is_form_submission:
                flash(f"Disk image registered: {filename} ({result.get('scheme', 'Hash verified')})", "success")
                return redirect(url_for("case_detail", case_id=case_id))

            return jsonify({**result, "id": item.id, "sha256": item.sha256, "analysis_status": item.analysis_status})
        except Exception:
            db.session.rollback()
            target.unlink(missing_ok=True)
            abort(500, "Disk-image registration failed")

    # --- CLI & Demo Seed Commands ---
    @app.cli.command("seed")
    @click.option("--reset", is_flag=True, help="Wipe and rebuild demo database from scratch")
    def seed_command(reset):
        """Seed the database with 3 synthetic demo cases, tampered evidence, and logs."""
        from services.seed import seed_demo_data

        result = seed_demo_data(app, reset=reset)
        click.echo(f"Demo seeding result: {result.get('message')}")
        for c in result.get("cases", []):
            click.echo(f"  * Case #{c['id']} [{c['status']}]: {c['title']}")
        if "tampered_evidence_id" in result:
            click.echo(
                f"  [TAMPER-TEST] Tampered Evidence ID #{result['tampered_evidence_id']} registered (for integrity failure testing)"
            )

    @app.post("/seed-demo")
    def seed_demo_route():
        """UI empty-state trigger to load synthetic demo cases."""
        from services.seed import seed_demo_data

        seed_demo_data(app, reset=False)
        flash("Synthetic demo cases loaded successfully into the workspace.", "success")
        return redirect(url_for("dashboard"))

    return app


if __name__ == "__main__":
    create_app().run(debug=False)
