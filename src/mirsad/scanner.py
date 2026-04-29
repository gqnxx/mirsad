from __future__ import annotations

import fnmatch
import re
from collections import Counter
from pathlib import Path

from .models import AttackPath, Finding, ScanReport, severity_meets
from .rules import BASE64_RE, HEX_RE, compiled_rules


DEFAULT_EXCLUDES = [
    ".git/**",
    ".hg/**",
    ".svn/**",
    ".venv/**",
    "venv/**",
    "env/**",
    "__pycache__/**",
    ".pytest_cache/**",
    ".ruff_cache/**",
    "node_modules/**",
    "dist/**",
    "build/**",
    "target/**",
    ".next/**",
    ".turbo/**",
    "coverage/**",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.webp",
    "*.ico",
    "*.pdf",
    "*.zip",
    "*.gz",
    "*.tar",
    "*.sqlite",
    "*.db",
    "*.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
]

DEFAULT_INCLUDES = [
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursor/rules/**",
    ".github/copilot-instructions.md",
    "README*",
    "docs/**",
    "prompts/**",
    "skills/**",
    "mcp.json",
    ".mcp/**",
    "server.json",
    ".env",
    ".env.*",
    "*.env",
    "*.md",
    "*.mdx",
    "*.txt",
    "*.json",
    "*.yaml",
    "*.yml",
    "*.toml",
]

SMART_INCLUDES = [
    *DEFAULT_INCLUDES,
    "*.py",
    "*.js",
    "*.jsx",
    "*.ts",
    "*.tsx",
    "*.go",
    "*.rs",
    "*.java",
    "*.rb",
    "*.php",
    "*.sh",
    "*.bash",
    "*.zsh",
    "*.ps1",
    "Dockerfile",
    "*.dockerfile",
    "Makefile",
    "package.json",
    "pyproject.toml",
]

DEEP_INCLUDES = ["*", "**/*"]

HIGH_PRIORITY_PATTERNS = [
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursor/rules/**",
    ".github/copilot-instructions.md",
    "prompts/**",
    "skills/**",
    "mcp.json",
    ".mcp/**",
    "server.json",
    ".env",
    ".env.*",
]

SEVERITY_SCORE = {
    "low": 15,
    "medium": 35,
    "high": 70,
    "critical": 95,
}

SCAN_MODES = {
    "focused": DEFAULT_INCLUDES,
    "smart": SMART_INCLUDES,
    "deep": DEEP_INCLUDES,
}

MAX_TEXT_BYTES = 1_000_000


def scan_path(
    root: Path,
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    fail_on: str = "high",
    mode: str = "smart",
) -> ScanReport:
    root = root.resolve()
    includes = include or SCAN_MODES[mode]
    excludes = [*DEFAULT_EXCLUDES, *(exclude or [])]
    files = collect_files(root, includes=includes, excludes=excludes)

    findings: list[Finding] = []
    skipped = 0

    for file_path in files:
        content = read_text_file(file_path)
        if content is None:
            skipped += 1
            continue
        findings.extend(scan_text(content, file_path.relative_to(root).as_posix()))

    findings.sort(key=lambda item: (severity_sort(item.severity), item.file, item.line), reverse=True)
    attack_paths = build_attack_paths(findings)
    status = status_for_findings(findings, fail_on)
    return ScanReport(
        status=status,
        risk_score=calculate_risk_score(findings),
        summary=build_summary(findings),
        findings=findings,
        attack_paths=attack_paths,
        scanned_files=len(files) - skipped,
        skipped_files=skipped,
    )


def collect_files(root: Path, *, includes: list[str], excludes: list[str]) -> list[Path]:
    if root.is_file():
        return [root]

    candidates: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if matches_any(rel, excludes):
            continue
        if matches_any(rel, includes):
            candidates.append(path)

    return sorted(candidates, key=lambda path: (priority_for(path.relative_to(root).as_posix()), path.as_posix()))


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def priority_for(path: str) -> int:
    return 0 if matches_any(path, HIGH_PRIORITY_PATTERNS) else 1


def read_text_file(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None

    if b"\x00" in data:
        return None

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("utf-8", errors="replace")
        except UnicodeError:
            return None


def scan_text(content: str, file_name: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule, pattern in compiled_rules():
        for match in pattern.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    file=file_name,
                    line=line,
                    severity=rule.severity,
                    category=rule.category,
                    excerpt=clean_excerpt(match.group(0)),
                    why_it_matters=rule.why_it_matters,
                    suggested_review=rule.suggested_review,
                    rule_id=rule.id,
                )
            )

    findings.extend(scan_obfuscated_tokens(content, file_name))
    findings.extend(scan_sensitive_assets(content, file_name))
    return dedupe_findings(findings)


def scan_obfuscated_tokens(content: str, file_name: str) -> list[Finding]:
    findings: list[Finding] = []
    for regex, label in ((BASE64_RE, "base64"), (HEX_RE, "hex")):
        for match in regex.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    file=file_name,
                    line=line,
                    severity="medium",
                    category="hidden_instruction",
                    excerpt=f"{label} blob: {match.group(0)[:48]}...",
                    why_it_matters="Long encoded blobs in agent-facing text can hide instructions from human reviewers.",
                    suggested_review="Decode and inspect the blob before letting an agent read this repository.",
                    rule_id=f"hidden-instruction-{label}-blob",
                )
            )
    return findings


def scan_sensitive_assets(content: str, file_name: str) -> list[Finding]:
    findings: list[Finding] = []
    if not is_sensitive_asset_file(file_name):
        return findings

    if re.search(r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY|OPENAI_API_KEY|GITHUB_TOKEN)", content, re.IGNORECASE):
        findings.append(
            Finding(
                file=file_name,
                line=1,
                severity="medium",
                category="sensitive_asset",
                excerpt="sensitive asset file contains secret-like names",
                why_it_matters="Secret-bearing files increase the impact of agent instructions that read or transmit local data.",
                suggested_review="Keep this file out of agent context unless it is a sanitized example.",
                rule_id="sensitive-asset-secret-like-file",
            )
        )
    return findings


def is_sensitive_asset_file(file_name: str) -> bool:
    path = Path(file_name)
    return path.name == ".env" or path.name.startswith(".env.") or path.suffix == ".env"


def clean_excerpt(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()[:220]


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.file, finding.line, finding.rule_id)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def status_for_findings(findings: list[Finding], fail_on: str) -> str:
    if not findings:
        return "pass"
    if any(severity_meets(finding.severity, fail_on) for finding in findings):
        return "block"
    return "review"


def build_summary(findings: list[Finding]) -> dict[str, dict[str, int]]:
    severity_counts = Counter(finding.severity for finding in findings)
    category_counts = Counter(finding.category for finding in findings)
    return {
        "severity": dict(sorted(severity_counts.items())),
        "category": dict(sorted(category_counts.items())),
    }


def calculate_risk_score(findings: list[Finding]) -> int:
    if not findings:
        return 0
    score = max(SEVERITY_SCORE[finding.severity] for finding in findings)
    score += min(30, max(0, len(findings) - 1) * 5)
    return min(100, score)


def severity_sort(severity: str) -> int:
    return SEVERITY_SCORE[severity]


def build_attack_paths(findings: list[Finding]) -> list[AttackPath]:
    instructions = [
        finding
        for finding in findings
        if finding.category in {"prompt_hijack", "secret_exfiltration", "dangerous_execution", "hidden_instruction"}
    ]
    capabilities = [
        finding
        for finding in findings
        if finding.category in {"agent_surface", "dangerous_execution"}
    ]
    assets = [
        finding
        for finding in findings
        if finding.category in {"sensitive_asset", "secret_exfiltration"}
    ]

    paths: list[AttackPath] = []
    for instruction in instructions:
        capability = nearest_finding(instruction, capabilities)
        asset = nearest_finding(instruction, assets)
        if not capability and not asset and instruction.category != "secret_exfiltration":
            continue
        paths.append(
            AttackPath(
                impact=impact_for(instruction, capability, asset),
                severity=attack_path_severity(instruction, capability, asset),
                instruction=instruction,
                capability=capability,
                asset=asset,
            )
        )

    return sorted(
        dedupe_attack_paths(paths),
        key=attack_path_sort_key,
        reverse=True,
    )[:3]


def nearest_finding(source: Finding, candidates: list[Finding]) -> Finding | None:
    usable = [candidate for candidate in candidates if candidate is not source]
    if not usable:
        return None
    same_file = [candidate for candidate in usable if candidate.file == source.file]
    pool = same_file or usable
    return sorted(pool, key=lambda item: abs(item.line - source.line))[0]


def impact_for(instruction: Finding, capability: Finding | None, asset: Finding | None) -> str:
    if instruction.category == "secret_exfiltration":
        if capability and asset:
            return "secret exfiltration path through agent instruction, tool capability, and sensitive asset"
        if capability:
            return "secret exfiltration path through agent instruction and executable capability"
        return "secret exposure path through agent instruction"
    if instruction.category == "dangerous_execution" or capability:
        return "agent tool execution path requiring manual review"
    if asset:
        return "agent instruction can interact with sensitive local data"
    return "agent-context manipulation path"


def attack_path_severity(
    instruction: Finding,
    capability: Finding | None,
    asset: Finding | None,
) -> str:
    if instruction.severity == "critical" or (instruction.category == "secret_exfiltration" and capability and asset):
        return "critical"
    if instruction.severity == "high" or capability:
        return "high"
    return "medium"


def dedupe_attack_paths(paths: list[AttackPath]) -> list[AttackPath]:
    seen: set[tuple[str, str, int]] = set()
    unique: list[AttackPath] = []
    for path in paths:
        key = (path.impact, path.instruction.file, path.instruction.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def attack_path_sort_key(path: AttackPath) -> tuple[int, int, int]:
    severity_rank = {"medium": 1, "high": 2, "critical": 3}[path.severity]
    completeness = int(path.capability is not None) + int(path.asset is not None)
    instruction_rank = severity_sort(path.instruction.severity)
    return severity_rank, completeness, instruction_rank
