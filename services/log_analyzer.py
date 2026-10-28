import re
from datetime import datetime
from pathlib import Path

# Severity detection patterns
SEVERITY_PATTERNS = [
    (re.compile(r"\b(CRITICAL|FATAL|EMERG|ALERT)\b", re.IGNORECASE), "CRITICAL"),
    (re.compile(r"\b(ERROR|ERR)\b", re.IGNORECASE), "ERROR"),
    (re.compile(r"\b(WARN|WARNING)\b", re.IGNORECASE), "WARNING"),
    (re.compile(r"\b(INFO|NOTICE)\b", re.IGNORECASE), "INFO"),
    (re.compile(r"\b(DEBUG|TRACE)\b", re.IGNORECASE), "DEBUG"),
]

# Timestamp regex patterns
TIMESTAMP_PATTERNS = [
    # ISO 8601: 2026-10-12 08:12:15 or 2026-10-12T08:12:15Z
    (re.compile(r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"), "%Y-%m-%d %H:%M:%S"),
    # Syslog: Oct 12 08:12:15
    (re.compile(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"), "%b %d %H:%M:%S"),
    # Apache/Nginx: 10/Oct/2026:13:55:36 +0000
    (re.compile(r"\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]"), "%d/%b/%Y:%H:%M:%S %z"),
    # Windows Event Log: 10/12/2026 08:12:15 AM
    (
        re.compile(r"\b(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)\b", re.IGNORECASE),
        "%m/%d/%Y %I:%M:%S %p",
    ),
]

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_PATTERN = re.compile(
    r"\b(?:user[=:\s]+|for\s+user\s+|for\s+|user\s+|invalid\s+user\s+)([a-zA-Z0-9_\-\.]+)\b",
    re.IGNORECASE,
)

# Forensic Detection Rules with strict regexes (safe on slashes and prefixes)
FAILED_LOGIN_PATTERN = re.compile(
    r"(?:failed\s+login|authentication\s+failure|invalid\s+password|login\s+failed|failed\s+password|(?:\b|,)(?:eventid[=:\s]+)?4625(?:\b|,))",
    re.IGNORECASE,
)
SUCCESS_LOGIN_PATTERN = re.compile(
    r"(?:accepted\s+(?:password|publickey)|session\s+opened|login\s+successful|successful\s+login|(?:\b|,)(?:eventid[=:\s]+)?4624(?:\b|,))",
    re.IGNORECASE,
)
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%2e%2e\\|/\.\.)",
    re.IGNORECASE,
)
SQLI_PATTERN = re.compile(
    r"(?:UNION\s+SELECT|OR\s+['\"]?1['\"]?\s*=\s*['\"]?1|\bWAITFOR\s+DELAY\b|;\s*DROP\s+TABLE\b|\bBENCHMARK\s*\(|\bAND\s+1\s*=\s*1\b)",
    re.IGNORECASE,
)
# Sensitive file regex: avoid \b directly before or after '/'
SENSITIVE_FILE_PATTERN = re.compile(
    r"(?:\A|[\s\"'`=:])(?:/etc/(?:shadow|passwd|sudoers|master\.passwd)|\bC:\\Windows\\System32\\config\\(?:SAM|SECURITY)\b|\bntds\.dit\b)",
    re.IGNORECASE,
)
PRIV_ESCALATION_PATTERN = re.compile(
    r"(?:\bsudo\s+(?:su|-i)\b|\bchmod\s+777\b|\bwhoami\s+/priv\b|\bpkexec\b|\bsetuid\b|\bsu\s+-\s+root\b)",
    re.IGNORECASE,
)


def _detect_severity(line: str) -> str:
    for pattern, name in SEVERITY_PATTERNS:
        if pattern.search(line):
            return name
    return "UNKNOWN"


def _parse_timestamp(line: str) -> datetime | None:
    for pattern, fmt in TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if match:
            ts_str = match.group(1).replace("T", " ").rstrip("Z")
            # Try parsing with datetime.fromisoformat first
            try:
                return datetime.fromisoformat(ts_str)
            except Exception:
                pass
            # Try specific strptime
            try:
                # Normalize spaces
                clean_str = " ".join(ts_str.split())
                parsed = datetime.strptime(clean_str, fmt)
                # Assign current year if missing (e.g. syslog)
                if parsed.year == 1900:
                    parsed = parsed.replace(year=datetime.now().year)
                return parsed
            except Exception:
                pass
    return None


def _extract_entities(line: str) -> tuple[str | None, str | None]:
    ip_match = IP_PATTERN.search(line)
    ip = ip_match.group(0) if ip_match else None

    user = None
    # Check Windows Security CSV format: TimeCreated,EventID,AccountName,...
    if "," in line and not line.startswith("#"):
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3 and parts[1] in ("4624", "4625"):
            user = parts[2]
            if not ip and len(parts) > 4 and IP_PATTERN.search(parts[4]):
                ip = parts[4]

    if not user:
        user_match = USER_PATTERN.search(line)
        if user_match:
            candidate = user_match.group(1)
            # Exclude false-positive generic words
            if candidate.lower() not in {"invalid", "authenticating", "failed", "accepted", "closed", "user"}:
                user = candidate

    return ip, user


def analyze_log(
    path: str | Path,
    keyword: str | None = None,
    severity: str | None = None,
    brute_force_threshold: int = 2,
    brute_force_window_seconds: int = 600,
    max_stored_events: int = 2000,
) -> dict:
    """
    Forensic Log Analysis Engine.
    Always analyzes ALL lines across structured detection rules.
    Keyword and severity filters are applied ONLY to the returned 'events' view.
    """
    path_obj = Path(path)
    if not path_obj.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    try:
        content = path_obj.read_text(encoding="utf-8", errors="replace")
    except Exception:
        content = path_obj.read_bytes().decode("latin-1", errors="replace")

    all_lines = content.splitlines()
    total_lines = len(all_lines)

    parsed_events = []
    severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0, "DEBUG": 0, "UNKNOWN": 0}

    # Tracking collections for stateful detections
    failed_logins_by_entity: dict[str, list[dict]] = {}
    success_logins_by_entity: dict[str, list[dict]] = {}

    traversal_events = []
    sqli_events = []
    sensitive_file_events = []
    priv_esc_events = []
    off_hours_events = []

    # 1. Parse and extract metadata for ALL lines
    for line_num, line in enumerate(all_lines, 1):
        line_sev = _detect_severity(line)
        severity_counts[line_sev] = severity_counts.get(line_sev, 0) + 1

        dt = _parse_timestamp(line)
        ip, user = _extract_entities(line)

        event_record = {
            "line": line_num,
            "line_number": line_num,
            "text": line,
            "severity": line_sev,
            "timestamp": dt.isoformat() if dt else None,
            "ip": ip,
            "user": user,
            "flagged": False,
        }

        # Rule checks
        is_failed = bool(FAILED_LOGIN_PATTERN.search(line))
        is_success = bool(SUCCESS_LOGIN_PATTERN.search(line))
        is_traversal = bool(PATH_TRAVERSAL_PATTERN.search(line))
        is_sqli = bool(SQLI_PATTERN.search(line))
        is_sensitive = bool(SENSITIVE_FILE_PATTERN.search(line))
        is_priv_esc = bool(PRIV_ESCALATION_PATTERN.search(line))

        is_off_hours = False
        if dt and (dt.hour < 6 or dt.hour >= 22 or dt.weekday() >= 5):
            is_off_hours = True

        entities_for_event = []
        if user:
            entities_for_event.append(f"user:{user}")
        if ip:
            entities_for_event.append(f"ip:{ip}")
        if not entities_for_event:
            entities_for_event.append("unknown")

        if is_failed:
            for ent in entities_for_event:
                failed_logins_by_entity.setdefault(ent, []).append(event_record)
        if is_success:
            for ent in entities_for_event:
                success_logins_by_entity.setdefault(ent, []).append(event_record)
        if is_traversal:
            traversal_events.append(event_record)
        if is_sqli:
            sqli_events.append(event_record)
        if is_sensitive:
            sensitive_file_events.append(event_record)
        if is_priv_esc:
            priv_esc_events.append(event_record)
        if is_off_hours and (line_sev in ("CRITICAL", "ERROR", "WARNING") or is_priv_esc or is_failed):
            off_hours_events.append(event_record)

        if any([is_failed, is_traversal, is_sqli, is_sensitive, is_priv_esc]) or (
            is_off_hours and (line_sev in ("CRITICAL", "ERROR", "WARNING") or is_priv_esc or is_failed)
        ):
            event_record["flagged"] = True

        parsed_events.append(event_record)

    findings = []
    flagged_line_numbers = set()

    # 2. Rule Detections

    # A. Brute Force Rule (per user | ip within time window)
    seen_bf_lines = set()
    for entity, records in failed_logins_by_entity.items():
        if len(records) >= brute_force_threshold:
            # Check time window if timestamps are available
            matched_window = False
            parsed_dts = [_parse_timestamp(r["text"]) for r in records]
            if all(d is not None for d in parsed_dts):
                for i in range(len(parsed_dts) - brute_force_threshold + 1):
                    window = (parsed_dts[i + brute_force_threshold - 1] - parsed_dts[i]).total_seconds()
                    if 0 <= window <= brute_force_window_seconds:
                        matched_window = True
                        break
            else:
                matched_window = True

            if matched_window:
                lines = [r["line"] for r in records]
                line_key = tuple(lines)
                if line_key in seen_bf_lines:
                    continue
                seen_bf_lines.add(line_key)
                flagged_line_numbers.update(lines)
                samples = [r["text"] for r in records[:3]]
                clean_name = entity.split(":", 1)[1] if ":" in entity else entity
                findings.append(
                    {
                        "rule_id": "RULE_BRUTE_FORCE",
                        "severity": "CRITICAL",
                        "title": f"Brute Force Authentication Lead ({clean_name})",
                        "reason": f"Repeated failed login attempts ({len(records)} events) detected for {clean_name}; investigative lead.",
                        "evidence_lines": lines,
                        "sample_lines": samples,
                        "entity": clean_name,
                        "events": len(records),
                    }
                )

    # B. Success After Failures Rule
    seen_saf_lines = set()
    for entity, succ_records in success_logins_by_entity.items():
        fail_records = failed_logins_by_entity.get(entity, [])
        if fail_records and succ_records:
            earliest_succ = succ_records[0]["line"]
            preceding_fails = [f for f in fail_records if f["line"] < earliest_succ]
            if preceding_fails:
                combined_lines = [f["line"] for f in preceding_fails] + [earliest_succ]
                line_key = tuple(combined_lines)
                if line_key in seen_saf_lines:
                    continue
                seen_saf_lines.add(line_key)
                flagged_line_numbers.update(combined_lines)
                clean_name = entity.split(":", 1)[1] if ":" in entity else entity
                findings.append(
                    {
                        "rule_id": "RULE_SUCCESS_AFTER_FAIL",
                        "severity": "CRITICAL",
                        "title": f"Authentication Success Following Failures ({clean_name})",
                        "reason": f"Successful login occurred after {len(preceding_fails)} failure(s) for identity '{clean_name}'.",
                        "evidence_lines": combined_lines,
                        "sample_lines": [preceding_fails[-1]["text"], succ_records[0]["text"]],
                        "entity": clean_name,
                        "events": len(combined_lines),
                    }
                )

    # C. Path Traversal Rule
    if traversal_events:
        lines = [r["line"] for r in traversal_events]
        flagged_line_numbers.update(lines)
        findings.append(
            {
                "rule_id": "RULE_PATH_TRAVERSAL",
                "severity": "WARNING",
                "title": "Directory Traversal Sequence",
                "reason": f"Directory traversal pattern (e.g. ../) identified across {len(traversal_events)} event(s).",
                "evidence_lines": lines,
                "sample_lines": [r["text"] for r in traversal_events[:3]],
                "entity": traversal_events[0].get("ip") or traversal_events[0].get("user"),
                "events": len(traversal_events),
            }
        )

    # D. SQL Injection Rule
    if sqli_events:
        lines = [r["line"] for r in sqli_events]
        flagged_line_numbers.update(lines)
        findings.append(
            {
                "rule_id": "RULE_SQLI",
                "severity": "CRITICAL",
                "title": "SQL Injection Pattern Detected",
                "reason": f"Suspicious SQL syntax or boolean injection payloads identified across {len(sqli_events)} event(s).",
                "evidence_lines": lines,
                "sample_lines": [r["text"] for r in sqli_events[:3]],
                "entity": sqli_events[0].get("ip") or sqli_events[0].get("user"),
                "events": len(sqli_events),
            }
        )

    # E. Sensitive File Access Rule
    if sensitive_file_events:
        lines = [r["line"] for r in sensitive_file_events]
        flagged_line_numbers.update(lines)
        findings.append(
            {
                "rule_id": "RULE_SENSITIVE_ACCESS",
                "severity": "CRITICAL",
                "title": "Sensitive System Credential File Access",
                "reason": f"Access references to sensitive system files (e.g., /etc/shadow, /etc/passwd, SAM) detected ({len(sensitive_file_events)} event(s)).",
                "evidence_lines": lines,
                "sample_lines": [r["text"] for r in sensitive_file_events[:3]],
                "entity": sensitive_file_events[0].get("ip") or sensitive_file_events[0].get("user"),
                "events": len(sensitive_file_events),
            }
        )

    # F. Privilege Escalation Rule
    if priv_esc_events:
        lines = [r["line"] for r in priv_esc_events]
        flagged_line_numbers.update(lines)
        findings.append(
            {
                "rule_id": "RULE_PRIV_ESCALATION",
                "severity": "CRITICAL",
                "title": "Privilege Escalation Command Detected",
                "reason": f"Privilege elevation or permission tampering commands (e.g. sudo su, chmod 777) identified ({len(priv_esc_events)} event(s)).",
                "evidence_lines": lines,
                "sample_lines": [r["text"] for r in priv_esc_events[:3]],
                "entity": priv_esc_events[0].get("user") or priv_esc_events[0].get("ip"),
                "events": len(priv_esc_events),
            }
        )

    # G. Off-Hours Activity Rule
    if off_hours_events:
        lines = [r["line"] for r in off_hours_events]
        flagged_line_numbers.update(lines)
        findings.append(
            {
                "rule_id": "RULE_OFF_HOURS",
                "severity": "LOW",
                "title": "Off-Hours Security Activity",
                "reason": f"Suspicious or elevated security events recorded during off-hours (22:00-06:00 or weekends) across {len(off_hours_events)} line(s).",
                "evidence_lines": lines,
                "sample_lines": [r["text"] for r in off_hours_events[:3]],
                "entity": None,
                "events": len(off_hours_events),
            }
        )

    # Update flagged status on parsed events
    for ev in parsed_events:
        if ev["line"] in flagged_line_numbers:
            ev["flagged"] = True

    # 3. Apply keyword / severity filters ONLY to the returned events view
    filtered_events = []
    for ev in parsed_events:
        if keyword and keyword.lower() not in ev["text"].lower():
            continue
        if severity and severity.upper() != "ALL" and severity.upper() != ev["severity"]:
            continue
        filtered_events.append(ev)

    # 4. Cap stored events: first max_stored_events + all flagged lines
    flagged_events = [ev for ev in parsed_events if ev["flagged"]]
    capped_events = parsed_events[:max_stored_events]
    capped_event_lines = {ev["line"] for ev in capped_events}
    for fev in flagged_events:
        if fev["line"] not in capped_event_lines:
            capped_events.append(fev)
            capped_event_lines.add(fev["line"])

    # If filter was applied, returned events is filtered_events; otherwise capped_events
    events_to_return = filtered_events if (keyword or severity) else capped_events

    return {
        "events_processed": len(all_lines),
        "total_lines": total_lines,
        "flagged_patterns": len(findings),
        "severity_counts": severity_counts,
        "events": events_to_return,
        "findings": findings,
    }
