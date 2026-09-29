import argparse
import sys
from pathlib import Path
from .scanner import scan_project
from .report import terminal_report, json_report, html_report, sarif_report

RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def parser():
    p = argparse.ArgumentParser(prog="promptshield", description="Local AI security static analyzer.")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="Scan a project directory.")
    s.add_argument("path")
    s.add_argument("--format", choices=["terminal", "json", "html", "sarif"], default="terminal")
    s.add_argument("--output", help="Write report to this file.")
    s.add_argument("--fail-on", choices=list(RANK), help="Exit 1 if findings reach this severity.")
    return p

def main(argv=None):
    args = parser().parse_args(argv)
    if args.command != "scan":
        return 0
    try:
        findings = scan_project(Path(args.path))
    except (FileNotFoundError, NotADirectoryError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    if args.format == "json":
        data = json_report(findings, args.path)
    elif args.format == "html":
        data = html_report(findings, args.path)
    elif args.format == "sarif":
        data = sarif_report(findings)
    else:
        data = terminal_report(findings, args.path)

    if args.output:
        Path(args.output).write_text(data, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(data)

    if args.fail_on and any(RANK[f.severity.value] >= RANK[args.fail_on] for f in findings):
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
