from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import SEVERITY_ORDER
from .reporters import render_report
from .scanner import SCAN_MODES, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mirsad",
        description="Pre-agent security check for hostile repository instructions.",
    )
    subcommands = parser.add_subparsers(dest="command")

    scan = subcommands.add_parser("scan", help="Scan a repository before an AI agent reads it")
    scan.add_argument("path", nargs="?", default=".", help="Repository or file path to scan")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high")
    scan.add_argument("--mode", choices=list(SCAN_MODES), default="smart")
    scan.add_argument("--output", help="Write report to a file")
    scan.add_argument("--include", action="append", default=[], help="Glob to include; can repeat")
    scan.add_argument("--exclude", action="append", default=[], help="Glob to exclude; can repeat")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = normalize_args(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 0

    target = Path(args.path)
    if not target.exists():
        print(f"mirsad: path does not exist: {target}", file=sys.stderr)
        return 2

    report = scan_path(
        target,
        include=args.include or None,
        exclude=args.exclude or None,
        fail_on=args.fail_on,
        mode=args.mode,
    )
    output = render_report(report, args.format)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")

    if report.status == "pass":
        return 0
    if report.status == "block":
        return 2
    return 1


def normalize_args(argv: list[str]) -> list[str]:
    if not argv:
        return ["scan", "."]
    if argv[0] == "scan":
        return argv
    return ["scan", *argv]


if __name__ == "__main__":
    raise SystemExit(main())
