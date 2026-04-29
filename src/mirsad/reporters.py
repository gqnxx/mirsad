from __future__ import annotations

import json

from .models import Finding, ScanReport


def render_report(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return render_json(report)
    if output_format == "sarif":
        return render_sarif(report)
    return render_text(report)


def render_text(report: ScanReport) -> str:
    if report.status == "pass":
        return (
            "PASS: safe to open with an agent\n"
            "No hostile agent instructions found.\n\n"
            f"Scanned files: {report.scanned_files}\n"
            f"Skipped files: {report.skipped_files}\n"
        )

    title = "BLOCKED" if report.status == "block" else "REVIEW"
    decision = (
        "Do not open this repo with an agent yet."
        if report.status == "block"
        else "Review these findings before agent use."
    )
    lines = [
        f"{title}: {len(report.findings)} finding(s), risk score {report.risk_score}",
        decision,
        "",
    ]
    if report.attack_paths:
        lines.append("Attack paths:")
        for index, path in enumerate(report.attack_paths, start=1):
            lines.extend(render_attack_path_text(index, path))
            lines.append("")
    for finding in report.findings:
        lines.extend(render_finding_text(finding))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_finding_text(finding: Finding) -> list[str]:
    return [
        f"{finding.severity.upper()}  {finding.file}:{finding.line}",
        finding.excerpt,
        f"Why: {finding.why_it_matters}",
        f"Review: {finding.suggested_review}",
    ]


def render_attack_path_text(index: int, path) -> list[str]:
    lines = [
        f"{index}. {path.severity.upper()}  {path.impact}",
        f"   instruction: {path.instruction.file}:{path.instruction.line} {path.instruction.excerpt}",
    ]
    if path.capability:
        lines.append(f"   capability:  {path.capability.file}:{path.capability.line} {path.capability.excerpt}")
    if path.asset:
        lines.append(f"   asset:       {path.asset.file}:{path.asset.line} {path.asset.excerpt}")
    return lines


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n"


def render_sarif(report: ScanReport) -> str:
    rules = {}
    for finding in report.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.category},
            "fullDescription": {"text": finding.why_it_matters},
            "help": {"text": finding.suggested_review},
            "properties": {
                "security-severity": sarif_security_severity(finding.severity),
                "tags": [finding.category, finding.severity],
            },
        }

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mirsad",
                        "informationUri": "https://github.com/gqnxx/mirsad",
                        "rules": list(rules.values()),
                    }
                },
                "results": [finding_to_sarif(finding) for finding in report.findings],
                "properties": {
                    "attack_paths": [path.to_dict() for path in report.attack_paths],
                },
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2) + "\n"


def finding_to_sarif(finding: Finding) -> dict[str, object]:
    return {
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": {"text": f"{finding.excerpt} {finding.why_it_matters}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region": {"startLine": finding.line},
                }
            }
        ],
        "properties": {
            "category": finding.category,
            "severity": finding.severity,
            "suggested_review": finding.suggested_review,
        },
    }


def sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def sarif_security_severity(severity: str) -> str:
    return {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.0",
        "low": "2.0",
    }[severity]
