from __future__ import annotations

from dataclasses import dataclass, field


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    pattern: str
    why_it_matters: str
    suggested_review: str
    flags: int = 0


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    severity: str
    category: str
    excerpt: str
    why_it_matters: str
    suggested_review: str
    rule_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "category": self.category,
            "excerpt": self.excerpt,
            "why_it_matters": self.why_it_matters,
            "suggested_review": self.suggested_review,
            "rule_id": self.rule_id,
        }


@dataclass(frozen=True)
class AttackPath:
    impact: str
    severity: str
    instruction: Finding
    capability: Finding | None = None
    asset: Finding | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "impact": self.impact,
            "severity": self.severity,
            "instruction": self.instruction.to_dict(),
            "capability": self.capability.to_dict() if self.capability else None,
            "asset": self.asset.to_dict() if self.asset else None,
        }


@dataclass
class ScanReport:
    status: str
    risk_score: int
    summary: dict[str, dict[str, int]]
    findings: list[Finding] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "attack_paths": [path.to_dict() for path in self.attack_paths],
            "findings": [finding.to_dict() for finding in self.findings],
        }


def severity_meets(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]
