from services.log_analyzer import analyze_log


def test_log_analysis_flags_repeated_failed_logins(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        "2026-10-01 10:00:00 ERROR failed login user=alice from 192.168.1.50\n"
        "2026-10-01 10:01:00 ERROR failed login user=alice from 192.168.1.50\n"
        "2026-10-01 10:02:00 ERROR failed login user=alice from 192.168.1.50\n",
        encoding="utf-8",
    )
    result = analyze_log(path, brute_force_threshold=3)
    assert result["events_processed"] == 3
    assert result["flagged_patterns"] >= 1
    bf_findings = [f for f in result["findings"] if f["rule_id"] == "RULE_BRUTE_FORCE"]
    assert len(bf_findings) == 1
    assert bf_findings[0]["entity"] in ("alice", "192.168.1.50")
    assert bf_findings[0]["evidence_lines"] == [1, 2, 3]


def test_log_analysis_success_after_failures(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        "2026-10-01 10:00:00 ERROR failed login user=bob from 10.0.0.2\n"
        "2026-10-01 10:01:00 ERROR failed login user=bob from 10.0.0.2\n"
        "2026-10-01 10:03:00 INFO Accepted password for user=bob from 10.0.0.2\n",
        encoding="utf-8",
    )
    result = analyze_log(path)
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "RULE_SUCCESS_AFTER_FAIL" in rule_ids


def test_sensitive_file_regex_positive_and_negative_cases(tmp_path):
    path = tmp_path / "sensitive.log"
    path.write_text(
        # Positive cases
        "2026-10-01 12:00:00 WARNING cat /etc/shadow\n"
        "2026-10-01 12:01:00 WARNING GET /etc/passwd HTTP/1.1\n"
        "2026-10-01 12:02:00 WARNING /etc/shadow opened\n"
        # Negative cases (should not trigger sensitive file access)
        "2026-10-01 12:03:00 INFO shadow_box rendered\n"
        "2026-10-01 12:04:00 INFO my_etc_shadow_backup is normal\n",
        encoding="utf-8",
    )
    result = analyze_log(path)
    sensitive_findings = [f for f in result["findings"] if f["rule_id"] == "RULE_SENSITIVE_ACCESS"]
    assert len(sensitive_findings) == 1
    assert sensitive_findings[0]["evidence_lines"] == [1, 2, 3]


def test_path_traversal_and_sqli_rules(tmp_path):
    path = tmp_path / "web.log"
    path.write_text(
        '192.168.1.100 - - [10/Oct/2026:13:55:36 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403\n'
        "192.168.1.100 - - [10/Oct/2026:13:56:01 +0000] \"POST /login payload=' OR '1'='1 HTTP/1.1\" 500\n"
        '192.168.1.100 - - [10/Oct/2026:13:57:00 +0000] "GET /clean_page.html HTTP/1.1" 200\n',
        encoding="utf-8",
    )
    result = analyze_log(path)
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "RULE_PATH_TRAVERSAL" in rule_ids
    assert "RULE_SQLI" in rule_ids


def test_privilege_escalation_and_off_hours(tmp_path):
    path = tmp_path / "system.log"
    path.write_text(
        "2026-10-01 02:30:00 CRITICAL sudo su root by user=hacker\n"
        "2026-10-01 02:35:00 WARNING chmod 777 /var/www/uploads\n",
        encoding="utf-8",
    )
    result = analyze_log(path)
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "RULE_PRIV_ESCALATION" in rule_ids
    assert "RULE_OFF_HOURS" in rule_ids


def test_filters_affect_only_events_view_not_analysis(tmp_path):
    path = tmp_path / "mixed.log"
    path.write_text(
        "2026-10-01 10:00:00 ERROR failed login user=alice\n"
        "2026-10-01 10:01:00 ERROR failed login user=alice\n"
        "2026-10-01 10:02:00 ERROR failed login user=alice\n"
        "2026-10-01 10:05:00 INFO routine heartbeat check\n",
        encoding="utf-8",
    )
    # Filter by keyword 'heartbeat'
    result = analyze_log(path, keyword="heartbeat")
    # The event view should only show the matched line
    assert len(result["events"]) == 1
    assert "routine heartbeat" in result["events"][0]["text"]
    # But findings must STILL detect the brute force from ALL lines
    assert result["flagged_patterns"] >= 1
    assert any(f["rule_id"] == "RULE_BRUTE_FORCE" for f in result["findings"])


def test_clean_baseline_produces_zero_findings(sample_data):
    baseline_file = sample_data / "clean_baseline.log"
    assert baseline_file.exists(), "sample_data/clean_baseline.log must exist"
    result = analyze_log(baseline_file)
    assert result["flagged_patterns"] == 0, f"Expected 0 findings but got: {result['findings']}"
    assert result["findings"] == []
    assert result["events_processed"] >= 5


def test_sample_data_auth_log_findings(sample_data):
    auth_file = sample_data / "auth.log"
    assert auth_file.exists()
    result = analyze_log(auth_file)
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert "RULE_BRUTE_FORCE" in rule_ids
    assert "RULE_SUCCESS_AFTER_FAIL" in rule_ids
    assert "RULE_PRIV_ESCALATION" in rule_ids


def test_sample_data_nginx_log_findings(sample_data):
    nginx_file = sample_data / "nginx_access.log"
    assert nginx_file.exists()
    result = analyze_log(nginx_file)
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert "RULE_PATH_TRAVERSAL" in rule_ids
    assert "RULE_SQLI" in rule_ids


def test_sample_data_windows_security_findings(sample_data):
    win_file = sample_data / "windows_security.csv"
    assert win_file.exists()
    result = analyze_log(win_file)
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert "RULE_BRUTE_FORCE" in rule_ids
    assert "RULE_SUCCESS_AFTER_FAIL" in rule_ids


def test_event_view_capping_to_2000_plus_flagged(tmp_path):
    log_path = tmp_path / "huge.log"
    # Write 2500 lines: 2498 benign lines, 2 flagged lines at lines 2400 and 2401
    lines = [f"2026-10-10 12:00:{i % 60:02d} INFO Routine daytime process {i}" for i in range(2500)]
    lines[2400] = "2026-10-10 12:00:00 CRITICAL sudo su root"
    lines[2401] = "2026-10-10 12:00:01 WARNING cat /etc/shadow"
    log_path.write_text("\n".join(lines), encoding="utf-8")

    result = analyze_log(log_path, max_stored_events=2000)
    assert result["events_processed"] == 2500
    assert result["flagged_patterns"] >= 2
    # The view should cap at first 2000 + the flagged lines beyond 2000
    assert len(result["events"]) <= 2005
    event_line_nums = {e["line_number"] for e in result["events"]}
    assert 2401 in event_line_nums
    assert 2402 in event_line_nums
