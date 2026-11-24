import argparse
import hashlib
import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SECRET_KV_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api_key|apikey|authorization)\s*=\s*([^\s&;\"']+)"
)

RULES: Dict[str, List[re.Pattern]] = {
    "Auth / Brute Force": [
        re.compile(r"(?i)\bfailed password\b"),
        re.compile(r"(?i)\binvalid user\b"),
        re.compile(r"(?i)\bauthentication failure\b"),
        re.compile(r"(?i)\btoo many authentication failures\b"),
    ],
    "Privilege Escalation": [
        re.compile(r"(?i)\bsudo:\b"),
        re.compile(r"(?i)\bUSER=root\b"),
        re.compile(r"(?i)\bsu\[\d+\]:\b"),
    ],
    "Web Exploitation / Recon": [
        re.compile(r"(?i)/etc/passwd\b"),
        re.compile(r"(?i)\b\.\./\.\./"),
        re.compile(r"(?i)(?:union\s+select|or\s+1=1|drop\s+table)"),
        re.compile(r'(?i)"\s+(?:403|500)\b'),
    ],
    "Sensitive Data / Auth Leak": [
        re.compile(r"(?i)\bpassword="),
        re.compile(r"(?i)\btoken="),
        re.compile(r"(?i)\bapi_key="),
    ],
}


class SessionRedactor:
    def __init__(self, salt: Optional[str] = None) -> None:
        self.salt = salt or os.urandom(16).hex()
        self.ip_map: Dict[str, str] = {}
        self.ip_counts: Counter = Counter()

    def token_for_ip(self, ip: str) -> str:
        if ip not in self.ip_map:
            digest = hashlib.sha256(f"{self.salt}:{ip}".encode("utf-8")).hexdigest()[:8]
            self.ip_map[ip] = f"<IP_{digest}>"
        self.ip_counts[self.ip_map[ip]] += 1
        return self.ip_map[ip]

    def redact(self, text: str) -> str:
        def _replace_ip(match: re.Match) -> str:
            return self.token_for_ip(match.group(0))

        def _replace_secret(match: re.Match) -> str:
            key = match.group(1)
            return f"{key}=<REDACTED>"

        redacted = IPV4_PATTERN.sub(_replace_ip, text)
        redacted = SECRET_KV_PATTERN.sub(_replace_secret, redacted)
        return redacted


@dataclass
class ScanReport:
    source_file: str
    total_lines: int = 0
    matched_lines: int = 0
    category_counts: Counter = field(default_factory=Counter)
    redacted_samples: List[str] = field(default_factory=list)
    ip_token_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source_file": self.source_file,
            "total_lines": self.total_lines,
            "matched_lines": self.matched_lines,
            "category_counts": dict(self.category_counts),
            "ip_token_counts": self.ip_token_counts,
            "redacted_samples": self.redacted_samples,
        }


def analyze_line(line: str) -> List[str]:
    matched_categories: List[str] = []
    for category, patterns in RULES.items():
        if any(pattern.search(line) for pattern in patterns):
            matched_categories.append(category)
    return matched_categories


def scan_log_file(
    log_path: Path,
    max_lines: int = 100,
    max_samples: int = 10,
    redactor: Optional[SessionRedactor] = None,
) -> ScanReport:
    if redactor is None:
        redactor = SessionRedactor()

    report = ScanReport(source_file=str(log_path))

    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if report.total_lines >= max_lines:
                break
            stripped = line.rstrip("\r\n")
            report.total_lines += 1

            categories = analyze_line(stripped)
            if categories:
                report.matched_lines += 1
                for cat in categories:
                    report.category_counts[cat] += 1
                redacted_line = redactor.redact(stripped)
                if len(report.redacted_samples) < max_samples:
                    report.redacted_samples.append(redacted_line)
            else:
                redactor.redact(stripped)

    report.ip_token_counts = dict(redactor.ip_counts)
    return report


def print_dry_run(report: ScanReport, top_ips: int = 10) -> None:
    print("=== LOG ANALYZER PRO (DRY-RUN) ===")
    print(f"Source file   : {report.source_file}")
    print(f"Total lines   : {report.total_lines}")
    print(f"Matched lines : {report.matched_lines}")
    print("\nCategories:")
    for cat, count in report.category_counts.most_common():
        print(f"  - {cat}: {count}")

    print(f"\nTop {top_ips} anonymized IP tokens:")
    sorted_ips = sorted(report.ip_token_counts.items(), key=lambda x: x[1], reverse=True)[:top_ips]
    for token, count in sorted_ips:
        print(f"  - {token}: {count}")

    print("\nRedacted sample lines:")
    for sample in report.redacted_samples:
        print(f"  * {sample}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Log Analyzer Pro CLI")
    parser.add_argument("log_file", help="Path to log file")
    parser.add_argument("--max-lines", type=int, default=100, help="Maximum lines to process")
    parser.add_argument("--top-ips", type=int, default=10, help="Number of top IP tokens to show")
    parser.add_argument("--dry-run", action="store_true", help="Run local analysis without AI API calls")
    parser.add_argument("--model", default="gpt-4o-mini", help="Model name for AI reporting")
    parser.add_argument("--output-md", help="Optional Markdown report path")
    parser.add_argument("--output-json", help="Optional JSON report path")
    args = parser.parse_args()

    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"Error: log file not found: {log_path}")
        return 1

    report = scan_log_file(log_path=log_path, max_lines=args.max_lines)

    if args.output_json:
        out_json = Path(args.output_json)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

    if args.output_md:
        out_md = Path(args.output_md)
        out_md.parent.mkdir(parents=True, exist_ok=True)
        lines_md = [
            f"# Security Log Report: `{report.source_file}`",
            "",
            f"- **Total lines:** {report.total_lines}",
            f"- **Matched lines:** {report.matched_lines}",
            "",
            "## Categories",
        ]
        for cat, count in report.category_counts.items():
            lines_md.append(f"- {cat}: {count}")
        lines_md.extend(["", "## Redacted Samples"])
        for sample in report.redacted_samples:
            lines_md.append(f"- `{sample}`")
        out_md.write_text("\n".join(lines_md) + "\n", encoding="utf-8")

    if args.dry_run or not args.output_md:
        print_dry_run(report, top_ips=args.top_ips)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
