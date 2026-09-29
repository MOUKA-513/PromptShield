import html
import json
from collections import Counter
from .models import WEIGHT, Finding

def score(findings):
    penalty = sum(WEIGHT[f.severity] for f in findings)
    return max(0, 100 - min(100, penalty))

def summary(findings):
    c = Counter(f.severity.value for f in findings)
    return {x: c.get(x, 0) for x in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}

def json_report(findings, target):
    return json.dumps({
        "tool": "PromptShield",
        "version": "1.0.0",
        "target": target,
        "security_score": score(findings),
        "summary": summary(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2)

def sarif_report(findings):
    rules = {}
    results = []
    for f in findings:
        rules.setdefault(f.rule_id, {"id": f.rule_id, "name": f.title})
        results.append({
            "ruleId": f.rule_id,
            "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}[f.severity.value],
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": f.line}
            }}]
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "PromptShield", "version": "1.0.0", "rules": list(rules.values())}},
            "results": results
        }]
    }, indent=2)

def html_report(findings, target):
    rows = []
    for f in findings:
        rows.append(f"""<tr>
<td><b>{html.escape(f.severity.value)}</b></td>
<td>{html.escape(f.rule_id)}</td>
<td>{html.escape(f.title)}</td>
<td>{html.escape(f.file)}:{f.line}</td>
<td><code>{html.escape(f.evidence)}</code></td>
<td>{html.escape(f.recommendation)}</td>
</tr>""")
    s = summary(findings)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>PromptShield Report</title>
<style>
body{{font-family:system-ui;margin:40px;background:#f6f7f9;color:#111}}
.card{{background:white;padding:24px;border-radius:14px;margin-bottom:20px}}
.score{{font-size:48px;font-weight:800}}
table{{width:100%;border-collapse:collapse;background:white}}
th,td{{padding:12px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}}
code{{white-space:pre-wrap}}
</style></head><body>
<div class="card"><h1>🛡️ PromptShield</h1><p>Security report for <b>{html.escape(target)}</b></p>
<div class="score">{score(findings)}/100</div>
<p>CRITICAL {s["CRITICAL"]} · HIGH {s["HIGH"]} · MEDIUM {s["MEDIUM"]} · LOW {s["LOW"]}</p></div>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="6">No findings detected.</td></tr>'}</tbody></table>
</body></html>"""

def terminal_report(findings, target):
    s = summary(findings)
    lines = [
        "", "╔══════════════════════════════════════════════╗",
        "║              🛡️  PROMPTSHIELD                ║",
        "║          AI SECURITY SCANNER v1.0             ║",
        "╚══════════════════════════════════════════════╝", "",
        f"Target: {target}", "", f"Security score: {score(findings)}/100", "",
        f"CRITICAL  {s['CRITICAL']}", f"HIGH      {s['HIGH']}",
        f"MEDIUM    {s['MEDIUM']}", f"LOW       {s['LOW']}", "",
        "Findings", "──────────────────────────────────────────────"
    ]
    for f in findings:
        lines += [f"{f.severity.value:<9} {f.rule_id} — {f.title}", f"          {f.file}:{f.line}", f"          {f.message}", f"          Fix: {f.recommendation}", ""]
    if not findings:
        lines.append("No findings detected.")
    return "\n".join(lines)
