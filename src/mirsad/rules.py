from __future__ import annotations

import re

from .models import Rule


RULES = [
    Rule(
        id="prompt-hijack-ignore-instructions",
        category="prompt_hijack",
        severity="high",
        pattern=r"\b(ignore|disregard|override)\b.{0,80}\b(previous|above|prior|system|developer)\b.{0,40}\b(instruction|prompt|message|rule)s?\b",
        flags=re.IGNORECASE,
        why_it_matters="Repo text can be injected into an agent context and attempt to override trusted instructions.",
        suggested_review="Treat this text as untrusted data and remove or isolate agent-directed override language.",
    ),
    Rule(
        id="prompt-hijack-system-prompt",
        category="prompt_hijack",
        severity="medium",
        pattern=r"\b(system prompt|developer message|hidden instruction|jailbreak|prompt injection)\b",
        flags=re.IGNORECASE,
        why_it_matters="Agent-facing text that references hidden prompts or jailbreaks can manipulate tool behavior.",
        suggested_review="Check whether this is documentation or an instruction intended to steer an agent.",
    ),
    Rule(
        id="secret-exfil-env-webhook",
        category="secret_exfiltration",
        severity="critical",
        pattern=r"\b(curl|wget|fetch|axios|requests\.(post|get)|http)\b.{0,120}(\$[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)|process\.env|\.env|env vars?|environment variables?)\b",
        flags=re.IGNORECASE,
        why_it_matters="A hidden instruction that combines network calls with secrets can lead to credential exfiltration.",
        suggested_review="Remove the instruction and verify no agent workflow can send secrets to external endpoints.",
    ),
    Rule(
        id="secret-exfil-read-env",
        category="secret_exfiltration",
        severity="high",
        pattern=r"\b(read|open|print|cat|dump|exfiltrate|send|upload)\b.{0,120}\b(\.env|env vars?|environment variables?|api key|token|secret|password|credentials?|diagnostics?)\b",
        flags=re.IGNORECASE,
        why_it_matters="Agents often have file and shell access; instructions to read or print secrets are high risk.",
        suggested_review="Confirm this is not agent-facing instruction text and remove secret-access directions.",
    ),
    Rule(
        id="dangerous-execution-shell",
        category="dangerous_execution",
        severity="high",
        pattern=r"\b(run|execute|eval|pipe|install)\b.{0,80}\b(curl\s+[^|]+\|\s*(sh|bash)|wget\s+[^|]+\|\s*(sh|bash)|rm\s+-rf|chmod\s+\+x|bash\s+-c|sh\s+-c)\b",
        flags=re.IGNORECASE,
        why_it_matters="Agent-directed shell execution can turn a malicious repo note into local code execution.",
        suggested_review="Require manual review before any agent follows this command.",
    ),
    Rule(
        id="dangerous-execution-no-confirm",
        category="dangerous_execution",
        severity="medium",
        pattern=r"\b(without asking|without confirmation|do not ask|auto[- ]?approve|silently)\b.{0,80}\b(run|execute|install|delete|push|deploy)\b",
        flags=re.IGNORECASE,
        why_it_matters="Instructions to skip approvals weaken human control over agent tool use.",
        suggested_review="Remove approval-bypass language from agent-facing files.",
    ),
    Rule(
        id="hidden-instruction-html-comment",
        category="hidden_instruction",
        severity="medium",
        pattern=r"<!--(?:(?!-->).){0,300}\b(agent|assistant|cursor|codex|claude|ignore|secret|token|\.env|curl)\b(?:(?!-->).){0,300}-->",
        flags=re.IGNORECASE | re.DOTALL,
        why_it_matters="Markdown comments are easy for humans to miss but can still be read by coding agents.",
        suggested_review="Inspect hidden comments and remove agent-directed instructions.",
    ),
    Rule(
        id="hidden-instruction-zero-width",
        category="hidden_instruction",
        severity="medium",
        pattern=r"[\u200b\u200c\u200d\ufeff]",
        why_it_matters="Zero-width characters can hide or obfuscate instructions in otherwise normal text.",
        suggested_review="Inspect the affected line with a viewer that reveals invisible Unicode characters.",
    ),
    Rule(
        id="agent-surface-mcp-command",
        category="agent_surface",
        severity="high",
        pattern=r'"(command|args)"\s*:\s*"(npx|uvx|bash|sh|python|node|curl|wget|powershell|cmd)"',
        flags=re.IGNORECASE,
        why_it_matters="MCP and agent tool configs can grant executable tools to an agent.",
        suggested_review="Verify the command source, pin versions, and avoid remote install scripts.",
    ),
    Rule(
        id="agent-surface-permissive-tools",
        category="agent_surface",
        severity="medium",
        pattern=r"\b(allow|enable|grant)\b.{0,80}\b(all tools|shell|terminal|filesystem|network|browser|write access)\b",
        flags=re.IGNORECASE,
        why_it_matters="Broad tool grants increase the blast radius of prompt injection.",
        suggested_review="Restrict tool access to the minimum needed for the task.",
    ),
]


BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")
HEX_RE = re.compile(r"\b(?:[a-fA-F0-9]{2}){48,}\b")


def compiled_rules() -> list[tuple[Rule, re.Pattern[str]]]:
    return [(rule, re.compile(rule.pattern, rule.flags)) for rule in RULES]
