import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from extensions import db
from models import Activity, Case, DiskImage, Evidence, LogAnalysis

TOOL_METADATA = {
    "name": "Digital Forensics Toolkit (DFT)",
    "version": "1.0.0-academic",
    "description": "Academic Prototype Single-User Digital Forensics Workbench",
}

# Register TrueType fonts for Unicode support if available
_FONTS_REGISTERED = False


def _register_report_fonts():
    global _FONTS_REGISTERED
    if _FONTS_REGISTERED:
        return
    font_dir = Path(__file__).resolve().parent.parent / "static" / "fonts"
    sans_path = font_dir / "IBMPlexSans-Variable.ttf"
    mono_path = font_dir / "IBMPlexMono-Regular.ttf"
    serif_path = font_dir / "IBMPlexSerif-SemiBold.ttf"

    try:
        if sans_path.is_file():
            pdfmetrics.registerFont(TTFont("IBMPlexSans", str(sans_path)))
        if mono_path.is_file():
            pdfmetrics.registerFont(TTFont("IBMPlexMono", str(mono_path)))
        if serif_path.is_file():
            pdfmetrics.registerFont(TTFont("IBMPlexSerif", str(serif_path)))
        _FONTS_REGISTERED = True
    except Exception:
        _FONTS_REGISTERED = False


def _sanitize_path(source_str: str) -> str:
    """Strips server filesystem root paths and returns only relative sanitized reference."""
    if not source_str:
        return ""
    p = Path(source_str)
    # Return last two path segments (e.g. 'uploads/uuid.txt') or just name
    parts = p.parts
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return p.name


def report_data(case_or_id) -> dict:
    """
    Aggregates case records into a forensic report dictionary.
    Strips internal server paths and includes verification status per evidence item.
    """
    if isinstance(case_or_id, Case):
        case = case_or_id
    else:
        case = db.session.get(Case, case_or_id)

    if case is None:
        from flask import abort

        abort(404, "Case not found")

    case_id = case.id
    now_utc = datetime.now(timezone.utc).isoformat()

    return {
        "tool": {
            **TOOL_METADATA,
            "generated_at": now_utc,
        },
        "case": {
            "id": case.id,
            "title": case.title,
            "investigator": case.investigator,
            "description": case.description or "",
            "status": case.status,
            "created_at": case.created_at.isoformat(),
        },
        "evidence": [
            {
                "id": e.id,
                "description": e.description,
                "storage_ref": _sanitize_path(e.source),
                "sha256": e.sha256,
                "collected_at": e.collected_at.isoformat() if e.collected_at else "",
                "examined_at": e.examined_at.isoformat() if e.examined_at else None,
                "last_verified_at": e.last_verified_at.isoformat() if e.last_verified_at else None,
                "last_verified_ok": e.last_verified_ok,
                "verification_status": e.status_label,
                "investigator": e.investigator,
            }
            for e in Evidence.query.filter_by(case_id=case_id).order_by(Evidence.collected_at.asc())
        ],
        "disk_images": [
            {
                "id": i.id,
                "filename": i.filename,
                "storage_ref": _sanitize_path(i.source),
                "sha256": i.sha256,
                "analysis_status": i.analysis_status,
                "results": json.loads(i.results_json) if i.results_json else {},
                "created_at": i.created_at.isoformat() if i.created_at else "",
            }
            for i in DiskImage.query.filter_by(case_id=case_id).order_by(DiskImage.created_at.asc())
        ],
        "logs": [
            {
                "filename": a.filename,
                "events_processed": a.events_processed,
                "flagged_patterns": a.flagged_patterns,
                "findings": json.loads(a.findings_json) if a.findings_json else {},
            }
            for a in LogAnalysis.query.filter_by(case_id=case_id).order_by(LogAnalysis.id.asc())
        ],
        "activities": [
            {
                "action": a.action_type,
                "result": a.result,
                "created_at": a.created_at.isoformat(),
            }
            for a in Activity.query.filter_by(case_id=case_id).order_by(Activity.created_at.asc())
        ],
    }


def csv_bytes(case_id_or_data) -> bytes:
    """Generates an organized, readable CSV report containing all forensic case artifacts."""
    if isinstance(case_id_or_data, dict):
        data = case_id_or_data
    else:
        data = report_data(case_id_or_data)
    stream = io.StringIO()
    writer = csv.writer(stream)

    writer.writerow(["section", "field_1", "field_2", "field_3", "field_4"])
    writer.writerow(["tool", "Name", data["tool"]["name"], "Version", data["tool"]["version"]])
    writer.writerow(["case", "ID", data["case"]["id"], "Title", data["case"]["title"]])
    writer.writerow(["case", "Investigator", data["case"]["investigator"], "Status", data["case"]["status"]])
    writer.writerow(["case", "Created", data["case"]["created_at"], "Description", data["case"]["description"]])
    writer.writerow([])

    writer.writerow(["evidence", "ID", "Filename", "SHA-256", "Verification Status", "Collected At"])
    for item in data["evidence"]:
        writer.writerow(
            [
                "evidence",
                item["id"],
                item["description"],
                item["sha256"],
                item["verification_status"],
                item.get("collected_at", ""),
            ]
        )
    writer.writerow([])

    writer.writerow(["disk_images", "ID", "Filename", "SHA-256", "Status"])
    for item in data["disk_images"]:
        writer.writerow(["disk_image", item["id"], item["filename"], item["sha256"], item["analysis_status"]])
    writer.writerow([])

    writer.writerow(["log_analyses", "Filename", "Events Processed", "Flagged Patterns", "Summary"])
    for item in data["logs"]:
        findings_count = item.get("flagged_patterns", 0)
        writer.writerow(
            [
                "log_analysis",
                item["filename"],
                item["events_processed"],
                findings_count,
                f"{findings_count} pattern(s) flagged",
            ]
        )
    writer.writerow([])

    writer.writerow(["audit_activities", "Action", "Result / Target", "Timestamp"])
    for item in data["activities"]:
        writer.writerow(["activity", item["action"], item["result"], item["created_at"]])

    return stream.getvalue().encode("utf-8")


def _truncate_text(text: any, max_len: int = 90) -> str:
    """Safely truncates string without replacing Unicode characters."""
    if text is None:
        return ""
    s = str(text).replace("\r", " ").replace("\n", " ")
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def pdf_bytes(case_id_or_data) -> bytes:
    """
    Generates a forensic PDF report with pagination, headers, footers,
    TrueType UTF-8 font support (non-ASCII preserved), and verified chain of custody.
    """
    _register_report_fonts()
    if isinstance(case_id_or_data, dict):
        data = case_id_or_data
    else:
        data = report_data(case_id_or_data)
    stream = io.BytesIO()
    doc = canvas.Canvas(stream, pagesize=letter)
    page_num = 1

    # Font definitions (use registered Plex fonts if available, fallback to standard Helvetica/Courier)
    body_font = "IBMPlexSans" if _FONTS_REGISTERED else "Helvetica"
    title_font = "IBMPlexSerif" if _FONTS_REGISTERED else "Helvetica-Bold"
    mono_font = "IBMPlexMono" if _FONTS_REGISTERED else "Courier"

    def draw_page_decorations(canvas_obj, p_num):
        canvas_obj.setFont(body_font, 8)
        canvas_obj.setFillColorRGB(0.3, 0.35, 0.4)
        canvas_obj.drawString(54, 760, "DIGITAL FORENSICS TOOLKIT · INVESTIGATIVE CASE LEDGER")
        canvas_obj.setStrokeColorRGB(0.8, 0.82, 0.85)
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(54, 752, 558, 752)

        # Footer
        canvas_obj.line(54, 45, 558, 45)
        canvas_obj.setFont(body_font, 8)
        canvas_obj.drawString(
            54, 32, f"Work Product · Generated {data['tool']['generated_at'][:19]} · {data['tool']['version']}"
        )
        canvas_obj.drawRightString(558, 32, f"Page {p_num}")

    draw_page_decorations(doc, page_num)
    y = 725

    def ensure_space(needed=20):
        nonlocal y, page_num
        if y - needed < 55:
            doc.showPage()
            page_num += 1
            draw_page_decorations(doc, page_num)
            y = 725

    # Case Header
    doc.setFont(title_font, 15)
    doc.setFillColorRGB(0.08, 0.09, 0.1)
    doc.drawString(54, y, _truncate_text(f"Case #{data['case']['id']}: {data['case']['title']}", 75))
    y -= 20

    doc.setFont(body_font, 9)
    doc.setFillColorRGB(0.25, 0.28, 0.32)
    doc.drawString(
        54,
        y,
        _truncate_text(
            f"Investigator: {data['case']['investigator']}  |  Status: {data['case']['status']}  |  Opened: {data['case']['created_at'][:10]}",
            85,
        ),
    )
    y -= 16

    if data["case"]["description"]:
        doc.setFont(body_font, 8.5)
        doc.setFillColorRGB(0.4, 0.44, 0.48)
        doc.drawString(54, y, _truncate_text(f"Scope: {data['case']['description']}", 95))
        y -= 20
    else:
        y -= 10

    # Section 1: Registered Evidence Items
    ensure_space(35)
    doc.setFont(title_font, 11)
    doc.setFillColorRGB(0.08, 0.09, 0.1)
    doc.drawString(54, y, f"1. Evidence Inventory ({len(data['evidence'])} item(s))")
    y -= 15

    if not data["evidence"]:
        doc.setFont(body_font, 8.5)
        doc.setFillColorRGB(0.45, 0.45, 0.45)
        doc.drawString(64, y, "No evidence files registered.")
        y -= 16
    else:
        for idx, item in enumerate(data["evidence"], 1):
            ensure_space(26)
            doc.setFont(body_font, 8.5)
            doc.setFillColorRGB(0.1, 0.12, 0.15)
            status_text = f"[{item['verification_status']}]"
            doc.drawString(64, y, _truncate_text(f"#{idx} {item['description']} · {status_text}"))
            y -= 11

            doc.setFont(mono_font, 7.5)
            doc.setFillColorRGB(0.3, 0.33, 0.38)
            doc.drawString(74, y, f"SHA-256: {item['sha256']}")
            y -= 13

    # Section 2: Disk Images
    y -= 8
    ensure_space(35)
    doc.setFont(title_font, 11)
    doc.setFillColorRGB(0.08, 0.09, 0.1)
    doc.drawString(54, y, f"2. Disk Images ({len(data['disk_images'])} item(s))")
    y -= 15

    if not data["disk_images"]:
        doc.setFont(body_font, 8.5)
        doc.setFillColorRGB(0.45, 0.45, 0.45)
        doc.drawString(64, y, "No raw disk images registered.")
        y -= 16
    else:
        for idx, img in enumerate(data["disk_images"], 1):
            ensure_space(24)
            doc.setFont(body_font, 8.5)
            doc.setFillColorRGB(0.1, 0.12, 0.15)
            doc.drawString(64, y, _truncate_text(f"#{idx} {img['filename']} ({img['analysis_status']})"))
            y -= 11

            doc.setFont(mono_font, 7.5)
            doc.setFillColorRGB(0.3, 0.33, 0.38)
            doc.drawString(74, y, f"SHA-256: {img['sha256']}")
            y -= 13

    # Section 3: Log Analyses & Findings
    y -= 8
    ensure_space(35)
    doc.setFont(title_font, 11)
    doc.setFillColorRGB(0.08, 0.09, 0.1)
    doc.drawString(54, y, f"3. Log Analyses & Investigative Leads ({len(data['logs'])} log(s))")
    y -= 15

    if not data["logs"]:
        doc.setFont(body_font, 8.5)
        doc.setFillColorRGB(0.45, 0.45, 0.45)
        doc.drawString(64, y, "No log files analyzed.")
        y -= 16
    else:
        for idx, log_item in enumerate(data["logs"], 1):
            ensure_space(24)
            doc.setFont(body_font, 8.5)
            doc.setFillColorRGB(0.1, 0.12, 0.15)
            doc.drawString(
                64,
                y,
                _truncate_text(
                    f"#{idx} {log_item['filename']} · {log_item['events_processed']} events · {log_item['flagged_patterns']} leads flagged"
                ),
            )
            y -= 12

            findings = log_item.get("findings", {}).get("findings", [])
            for finding in findings:
                ensure_space(14)
                doc.setFont(body_font, 8)
                doc.setFillColorRGB(0.78, 0.2, 0.1)  # Vermilion signal color
                doc.drawString(74, y, _truncate_text(f"• Lead: {finding.get('reason', '')}"))
                y -= 11

    # Section 4: Chain of Custody / Activity Trail
    y -= 8
    ensure_space(35)
    doc.setFont(title_font, 11)
    doc.setFillColorRGB(0.08, 0.09, 0.1)
    doc.drawString(54, y, f"4. Chain of Custody & Activity Ledger ({len(data['activities'])} action(s))")
    y -= 15

    if not data["activities"]:
        doc.setFont(body_font, 8.5)
        doc.setFillColorRGB(0.45, 0.45, 0.45)
        doc.drawString(64, y, "No recorded custody activities.")
    else:
        for act in data["activities"]:
            ensure_space(14)
            doc.setFont(body_font, 7.5)
            doc.setFillColorRGB(0.2, 0.22, 0.25)
            time_str = act["created_at"][:19].replace("T", " ")
            action_str = act["action"].replace("_", " ").title()
            doc.drawString(64, y, _truncate_text(f"{time_str} · {action_str}: {act['result']}", 95))
            y -= 11

    doc.save()
    return stream.getvalue()
