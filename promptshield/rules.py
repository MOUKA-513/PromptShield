import re
from .models import Finding, Severity

SECRET_PATTERNS = [
    (re.compile(r'(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*["\'][A-Za-z0-9_\-]{12,}["\']'), "Hard-coded credential", "Move credentials to environment variables or a secret manager."),
    (re.compile(r'(?i)\b(password|passwd|pwd)\b\s*[:=]\s*["\'][^"\']{6,}["\']'), "Hard-coded password", "Do not store passwords in source code."),
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), "Private-key material", "Remove private keys from source and rotate exposed credentials."),
]

INJECTION_PATTERNS = [
    re.compile(r'(?i)ignore\s+(all\s+)?previous\s+instructions'),
    re.compile(r'(?i)disregard\s+(all\s+)?prior\s+instructions'),
    re.compile(r'(?i)(reveal|show|print)\s+(the\s+)?(system|hidden)\s+prompt'),
    re.compile(r'(?i)you\s+are\s+now\s+(unrestricted|developer|admin)'),
    re.compile(r'(?i)override\s+(your|the)\s+(system|safety)\s+instructions'),
]

TOOL_PATTERNS = [
    re.compile(r'(?i)\b(shell|terminal|exec|execute_command|run_command)\b'),
    re.compile(r'(?i)\b(delete_file|remove_file|rm\s+-rf)\b'),
]

def finding(rule, severity, title, message, recommendation, file, line, evidence):
    return Finding(rule, Severity(severity), title, message, recommendation, file, line, evidence.strip())

def _lines(text):
    return enumerate(text.splitlines(), 1)

def scan_line(line, file, line_no):
    out = []
    for pattern, title, recommendation in SECRET_PATTERNS:
        if pattern.search(line):
            out.append(finding("PS001", "CRITICAL", title, "A credential-like value appears embedded in source.", recommendation, file, line_no, line))
            break
    if any(p.search(line) for p in INJECTION_PATTERNS):
        out.append(finding("PS002", "HIGH", "Potential prompt-injection instruction", "The text attempts to override instructions or expose hidden prompt content.", "Treat external text as untrusted data and delimit it from system instructions.", file, line_no, line))
    if any(p.search(line) for p in TOOL_PATTERNS):
        out.append(finding("PS003", "HIGH", "Potentially dangerous tool capability", "The line references command execution or destructive capabilities.", "Use least privilege, allowlists, argument validation, and explicit user approval.", file, line_no, line))
    if re.search(r'(?i)\bhttps?://', line) and any(x in line.lower() for x in ("tool", "agent", "webhook", "fetch", "upload", "download")):
        out.append(finding("PS004", "MEDIUM", "External endpoint used by agent/tool", "An agent-related line references an external network endpoint.", "Review the destination and avoid sending sensitive data by default.", file, line_no, line))
    if re.search(r'http://', line, re.I):
        out.append(finding("PS006", "HIGH", "Insecure HTTP endpoint", "HTTP traffic is unencrypted in transit.", "Use HTTPS unless an isolated local connection explicitly requires HTTP.", file, line_no, line))
    if re.search(r'(?i)(allow_all|allow_any|permissions\s*=\s*["\']?\*|tools\s*=\s*\[["\']?\*["\']?\])', line):
        out.append(finding("PS007", "HIGH", "Wildcard tool permission", "A wildcard permission may grant an agent more capabilities than intended.", "Replace wildcards with an explicit least-privilege allowlist.", file, line_no, line))
    if re.search(r'(?i)(auto[_ -]?approve|skip[_ -]?confirmation|no[_ -]?confirmation)', line):
        out.append(finding("PS008", "MEDIUM", "Tool confirmation disabled", "The configuration appears to bypass user confirmation for an agent action.", "Require confirmation for destructive or externally visible actions.", file, line_no, line))
    if re.search(r'(?i)(read[_ -]?all|filesystem[_ -]?root\s*=\s*["\']?[/~]|access[_ -]?home|all[_ -]?files)', line):
        out.append(finding("PS009", "MEDIUM", "Broad data access", "The configuration may grant access to a broad filesystem or data scope.", "Restrict data access to the minimum required directories and resources.", file, line_no, line))
    return out

def scan_text(text, file):
    findings = []
    for line_no, line in _lines(text):
        findings.extend(scan_line(line, file, line_no))
    return findings

def apply_rule_config(findings, rules):
    out = []
    for f in findings:
        severity = rules.get(f.rule_id)
        if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            out.append(Finding(f.rule_id, Severity(severity), f.title, f.message, f.recommendation, f.file, f.line, f.evidence))
    return out
