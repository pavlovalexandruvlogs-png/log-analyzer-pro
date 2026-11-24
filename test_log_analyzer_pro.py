from pathlib import Path
from log_analyzer_pro import SessionRedactor, analyze_line, scan_log_file


def test_session_redactor_deterministic_and_masks_secret():
    redactor = SessionRedactor(salt="fixed-test-salt")
    line1 = "Failed password for admin from 203.0.113.45 port 51201"
    line2 = "GET /login?user=test&password=SecretPassword123 HTTP/1.1"

    r1 = redactor.redact(line1)
    r2 = redactor.redact(line2)

    assert "203.0.113.45" not in r1
    assert "<IP_" in r1
    assert "SecretPassword123" not in r2
    assert "password=<REDACTED>" in r2


def test_analyze_line_categories():
    assert "Auth / Brute Force" in analyze_line("Failed password for invalid user admin from 1.2.3.4")
    assert "Privilege Escalation" in analyze_line("sudo: user1 : USER=root ; COMMAND=/bin/sh")
    assert "Web Exploitation / Recon" in analyze_line('1.2.3.4 - - [x] "GET /etc/passwd HTTP/1.1" 403 100')


def test_scan_log_file_counts(tmp_path: Path):
    sample = tmp_path / "test.log"
    sample.write_text(
        "\n".join([
            "Failed password for admin from 203.0.113.45 port 22",
            "Failed password for root from 203.0.113.45 port 22",
            "Routine health check OK",
        ]) + "\n",
        encoding="utf-8",
    )

    report = scan_log_file(sample, max_lines=50)
    assert report.total_lines == 3
    assert report.matched_lines == 2
    assert report.category_counts["Auth / Brute Force"] == 2
    assert sum(report.ip_token_counts.values()) == 2
