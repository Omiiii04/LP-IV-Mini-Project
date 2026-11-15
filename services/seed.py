"""Demo database seeder for Digital Forensics Toolkit.

Populates 3 forensic cases across different lifecycle statuses:
- Case 1 (Open): Operation Chimera - Corporate Data Exfiltration (with a deliberately tampered file)
- Case 2 (In Progress): Incident 2026-088 - Staging Gateway Infiltration
- Case 3 (Closed): Audit 2026-Q3 - Workstation Decommission Verification

All files and logs are synthetic and sourced from sample_data/.
"""

import json
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from extensions import db
from models import Activity, Case, Evidence, LogAnalysis, Report, utcnow
from services.hashing import hash_bytes
from services.log_analyzer import analyze_log
from services.report_generator import csv_bytes, pdf_bytes, report_data


def seed_demo_data(app, reset: bool = False) -> dict:
    """Seeds 3 demo forensic cases with evidence, tampered artifacts, logs, and reports."""
    repo_root = Path(app.root_path)
    sample_data_dir = repo_root / "sample_data"
    storage_root = Path(app.config["STORAGE_ROOT"]).resolve()
    storage_root.mkdir(parents=True, exist_ok=True)
    uploads_dir = storage_root / "uploads"
    reports_dir = storage_root / "reports"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    with app.app_context():
        demo_titles = {
            "Operation Chimera - Corporate Data Exfiltration",
            "Incident 2026-088 - Staging Gateway Infiltration",
            "Audit 2026-Q3 - Workstation Decommission Verification",
        }

        if reset:
            existing_demo_cases = Case.query.filter(Case.title.in_(demo_titles)).all()
            for c in existing_demo_cases:
                for ev in c.evidence:
                    p = storage_root / ev.source
                    p.unlink(missing_ok=True)
                db.session.delete(c)
            db.session.commit()
        else:
            first_existing = Case.query.filter_by(title="Operation Chimera - Corporate Data Exfiltration").first()
            if first_existing:
                return {"message": "Demo data already loaded.", "case_ids": [first_existing.id]}

        base_time = utcnow() - timedelta(days=5)

        # -------------------------------------------------------------
        # CASE 1: Open - Operation Chimera (Contains Deliberately Tampered File)
        # -------------------------------------------------------------
        case1 = Case(
            title="Operation Chimera - Corporate Data Exfiltration",
            investigator="Dr. Elena Rostova",
            description=(
                "Investigation into unauthorized external egress towards 198.51.100.44:8443, "
                "credential stuffing on internal servers, and deliberate file tampering."
            ),
            status="Open",
            created_at=base_time,
        )
        db.session.add(case1)
        db.session.commit()
        db.session.add(
            Activity(
                case_id=case1.id,
                action_type="case_created",
                result=case1.title,
                created_at=base_time,
            )
        )

        # Evidence 1.1: Confidential Memo (Intact)
        memo_content = (
            "CONFIDENTIAL // PROJECT CHIMERA\n"
            "Classification: Restricted Internal Distribution\n"
            "Target Destination: 198.51.100.44:8443 (Encrypted Tunnel)\n"
            "Payload Hash: 8f9b23a7e4c19d204a8b71f92e482701b\n"
        ).encode("utf-8")
        memo_name = "confidential_project_chimera.txt"
        memo_rel = f"uploads/{uuid4().hex}_{memo_name}"
        memo_dest = storage_root / memo_rel
        memo_dest.write_bytes(memo_content)
        memo_hash = hash_bytes(memo_content)["sha256"]

        ev1 = Evidence(
            case_id=case1.id,
            description=memo_name,
            source=memo_rel,
            sha256=memo_hash,
            investigator=case1.investigator,
            collected_at=base_time + timedelta(minutes=10),
            examined_at=base_time + timedelta(hours=1),
            last_verified_at=base_time + timedelta(hours=1),
            last_verified_ok=True,
        )
        db.session.add(ev1)
        db.session.add(
            Activity(
                case_id=case1.id,
                action_type="evidence_registered",
                result=f"{memo_name} (SHA-256: {memo_hash[:8]}...)",
                created_at=base_time + timedelta(minutes=10),
            )
        )
        db.session.add(
            Activity(
                case_id=case1.id,
                action_type="evidence_verified",
                result=f"{memo_name} hash verified intact",
                created_at=base_time + timedelta(hours=1),
            )
        )

        # Evidence 1.2: Network Triage CSV (DELIBERATELY TAMPERED FILE)
        csv_original = (
            "timestamp,src_ip,dest_ip,bytes,alert\n"
            "2026-10-12T08:14:02Z,192.168.1.105,10.0.0.1,1420,NONE\n"
            "2026-10-12T08:15:30Z,192.168.1.105,198.51.100.44,8492004,ALERT_EXFIL\n"
        ).encode("utf-8")
        csv_name = "perimeter_network_triage.csv"
        csv_rel = f"uploads/{uuid4().hex}_{csv_name}"
        csv_dest = storage_root / csv_rel
        csv_orig_hash = hash_bytes(csv_original)["sha256"]

        # DELIBERATELY WRITE TAMPERED BYTES TO DISK
        tampered_content = (
            b"TAMPERED_CONTENT: Hostile actor replaced original forensic triage log with invalid payload."
        )
        csv_dest.write_bytes(tampered_content)

        ev2 = Evidence(
            case_id=case1.id,
            description=csv_name,
            source=csv_rel,
            sha256=csv_orig_hash,  # Baseline recorded hash
            investigator=case1.investigator,
            collected_at=base_time + timedelta(minutes=20),
            examined_at=base_time + timedelta(hours=2),
            last_verified_at=base_time + timedelta(hours=3),
            last_verified_ok=False,  # Verified and failed!
        )
        db.session.add(ev2)
        db.session.add(
            Activity(
                case_id=case1.id,
                action_type="evidence_registered",
                result=f"{csv_name} (SHA-256: {csv_orig_hash[:8]}...)",
                created_at=base_time + timedelta(minutes=20),
            )
        )
        db.session.add(
            Activity(
                case_id=case1.id,
                action_type="evidence_integrity_failure",
                result=f"ALERT: Integrity check failed on {csv_name}! Stored hash does not match disk bytes.",
                created_at=base_time + timedelta(hours=3),
            )
        )

        # Evidence 1.3: Investigator Notes
        notes_src = sample_data_dir / "notes.txt"
        if notes_src.exists():
            notes_bytes = notes_src.read_bytes()
            notes_name = "notes.txt"
            notes_rel = f"uploads/{uuid4().hex}_{notes_name}"
            (storage_root / notes_rel).write_bytes(notes_bytes)
            notes_hash = hash_bytes(notes_bytes)["sha256"]
            ev3 = Evidence(
                case_id=case1.id,
                description=notes_name,
                source=notes_rel,
                sha256=notes_hash,
                investigator=case1.investigator,
                collected_at=base_time + timedelta(hours=3, minutes=30),
                examined_at=base_time + timedelta(hours=4),
                last_verified_at=base_time + timedelta(hours=4),
                last_verified_ok=True,
            )
            db.session.add(ev3)
            db.session.add(
                Activity(
                    case_id=case1.id,
                    action_type="evidence_registered",
                    result=notes_name,
                    created_at=base_time + timedelta(hours=3, minutes=30),
                )
            )

        # Logs: auth.log and nginx_access.log
        auth_src = sample_data_dir / "auth.log"
        if auth_src.exists():
            auth_res = analyze_log(auth_src)
            db.session.add(
                LogAnalysis(
                    case_id=case1.id,
                    filename="auth.log",
                    events_processed=auth_res["events_processed"],
                    flagged_patterns=auth_res["flagged_patterns"],
                    findings_json=json.dumps(auth_res),
                )
            )
            db.session.add(
                Activity(
                    case_id=case1.id,
                    action_type="log_analyzed",
                    result=f"auth.log ({auth_res['flagged_patterns']} leads flagged: brute force, sudo)",
                    created_at=base_time + timedelta(hours=5),
                )
            )

        nginx_src = sample_data_dir / "nginx_access.log"
        if nginx_src.exists():
            nginx_res = analyze_log(nginx_src)
            db.session.add(
                LogAnalysis(
                    case_id=case1.id,
                    filename="nginx_access.log",
                    events_processed=nginx_res["events_processed"],
                    flagged_patterns=nginx_res["flagged_patterns"],
                    findings_json=json.dumps(nginx_res),
                )
            )
            db.session.add(
                Activity(
                    case_id=case1.id,
                    action_type="log_analyzed",
                    result=f"nginx_access.log ({nginx_res['flagged_patterns']} leads flagged: traversal, SQLi)",
                    created_at=base_time + timedelta(hours=6),
                )
            )

        # Generate Reports for Case 1 (JSON, CSV, PDF)
        db.session.commit()
        data1 = report_data(case1)

        # JSON Report
        j_bytes = json.dumps(data1, indent=2).encode("utf-8")
        j_hash = hash_bytes(j_bytes)["sha256"]
        db.session.add(
            Report(
                case_id=case1.id,
                report_format="json",
                sha256=j_hash,
                generated_at=base_time + timedelta(hours=8),
            )
        )

        # CSV Report
        c_bytes = csv_bytes(data1)
        c_hash = hash_bytes(c_bytes)["sha256"]
        db.session.add(
            Report(
                case_id=case1.id,
                report_format="csv",
                sha256=c_hash,
                generated_at=base_time + timedelta(hours=8, minutes=5),
            )
        )

        # PDF Report
        p_bytes = pdf_bytes(data1)
        p_hash = hash_bytes(p_bytes)["sha256"]
        db.session.add(
            Report(
                case_id=case1.id,
                report_format="pdf",
                sha256=p_hash,
                generated_at=base_time + timedelta(hours=8, minutes=10),
            )
        )
        db.session.add(
            Activity(
                case_id=case1.id,
                action_type="report_generated",
                result=f"Comprehensive case reports generated (JSON, CSV, PDF; SHA-256: {p_hash[:8]}...)",
                created_at=base_time + timedelta(hours=8, minutes=10),
            )
        )

        # -------------------------------------------------------------
        # CASE 2: In Progress - Incident 2026-088
        # -------------------------------------------------------------
        case2_time = utcnow() - timedelta(days=2)
        case2 = Case(
            title="Incident 2026-088 - Staging Gateway Infiltration",
            investigator="Marcus Vance",
            description="Active examination of the staging cluster gateway and baseline log activity.",
            status="In Progress",
            created_at=case2_time,
        )
        db.session.add(case2)
        db.session.commit()
        db.session.add(
            Activity(
                case_id=case2.id,
                action_type="case_created",
                result=case2.title,
                created_at=case2_time,
            )
        )

        # Evidence: small.pdf
        pdf_src = sample_data_dir / "small.pdf"
        if pdf_src.exists():
            p_bytes = pdf_src.read_bytes()
            p_rel = f"uploads/{uuid4().hex}_small.pdf"
            (storage_root / p_rel).write_bytes(p_bytes)
            p_hash = hash_bytes(p_bytes)["sha256"]
            ev_pdf = Evidence(
                case_id=case2.id,
                description="incident_notification.pdf",
                source=p_rel,
                sha256=p_hash,
                investigator=case2.investigator,
                collected_at=case2_time + timedelta(minutes=15),
                examined_at=case2_time + timedelta(hours=1),
                last_verified_at=case2_time + timedelta(hours=1),
                last_verified_ok=True,
            )
            db.session.add(ev_pdf)
            db.session.add(
                Activity(
                    case_id=case2.id,
                    action_type="evidence_registered",
                    result="incident_notification.pdf",
                    created_at=case2_time + timedelta(minutes=15),
                )
            )

        # Logs: clean_baseline.log (demonstrates 0 findings)
        clean_src = sample_data_dir / "clean_baseline.log"
        if clean_src.exists():
            clean_res = analyze_log(clean_src)
            db.session.add(
                LogAnalysis(
                    case_id=case2.id,
                    filename="clean_baseline.log",
                    events_processed=clean_res["events_processed"],
                    flagged_patterns=clean_res["flagged_patterns"],
                    findings_json=json.dumps(clean_res),
                )
            )
            db.session.add(
                Activity(
                    case_id=case2.id,
                    action_type="log_analyzed",
                    result="clean_baseline.log (0 flagged patterns — normal operations verified)",
                    created_at=case2_time + timedelta(hours=2),
                )
            )

        # -------------------------------------------------------------
        # CASE 3: Closed - Audit 2026-Q3 (Decommission Verification)
        # -------------------------------------------------------------
        case3_time = utcnow() - timedelta(days=14)
        case3 = Case(
            title="Audit 2026-Q3 - Workstation Decommission Verification",
            investigator="Sarah Jenkins",
            description="Sanitization verification and evidentiary sign-off for retired endpoint hardware.",
            status="Closed",
            created_at=case3_time,
        )
        db.session.add(case3)
        db.session.commit()
        db.session.add(
            Activity(
                case_id=case3.id,
                action_type="case_created",
                result=case3.title,
                created_at=case3_time,
            )
        )

        # Evidence: Windows security event export
        windows_src = sample_data_dir / "windows_security.csv"
        if windows_src.exists():
            windows_bytes = windows_src.read_bytes()
            windows_rel = f"uploads/{uuid4().hex}_windows_security.csv"
            (storage_root / windows_rel).write_bytes(windows_bytes)
            windows_hash = hash_bytes(windows_bytes)["sha256"]
            ev_raw = Evidence(
                case_id=case3.id,
                description="windows_security_export.csv",
                source=windows_rel,
                sha256=windows_hash,
                investigator=case3.investigator,
                collected_at=case3_time + timedelta(minutes=30),
                examined_at=case3_time + timedelta(hours=2),
                last_verified_at=case3_time + timedelta(hours=2),
                last_verified_ok=True,
            )
            db.session.add(ev_raw)
            db.session.add(
                Activity(
                    case_id=case3.id,
                    action_type="evidence_registered",
                    result="windows_security_export.csv",
                    created_at=case3_time + timedelta(minutes=30),
                )
            )

        # Generate closed case report
        db.session.commit()
        data3 = report_data(case3)
        p3_bytes = pdf_bytes(data3)
        p3_hash = hash_bytes(p3_bytes)["sha256"]
        db.session.add(
            Report(
                case_id=case3.id,
                report_format="pdf",
                sha256=p3_hash,
                generated_at=case3_time + timedelta(days=1),
            )
        )
        db.session.add(
            Activity(
                case_id=case3.id,
                action_type="report_generated",
                result=f"Final Decommission Audit PDF signed off (SHA-256: {p3_hash[:8]}...)",
                created_at=case3_time + timedelta(days=1),
            )
        )
        db.session.add(
            Activity(
                case_id=case3.id,
                action_type="case_closed",
                result="Case closed by Compliance Officer Sarah Jenkins",
                created_at=case3_time + timedelta(days=1, hours=2),
            )
        )

        db.session.commit()

        return {
            "message": "Demo data successfully seeded.",
            "cases": [
                {"id": case1.id, "title": case1.title, "status": case1.status},
                {"id": case2.id, "title": case2.title, "status": case2.status},
                {"id": case3.id, "title": case3.title, "status": case3.status},
            ],
            "tampered_evidence_id": ev2.id,
        }
