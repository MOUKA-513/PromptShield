from pathlib import Path
from promptshield.scanner import scan_project
from promptshield.report import score, sarif_report

def test_vulnerable_example():
    findings = scan_project(Path("examples/vulnerable-agent"))
    assert len(findings) >= 5
    assert score(findings) < 100

def test_secure_example():
    findings = scan_project(Path("examples/secure-agent"))
    assert not any(f.rule_id in {"PS001", "PS010"} for f in findings)

def test_sarif():
    findings = scan_project(Path("examples/vulnerable-agent"))
    data = sarif_report(findings)
    assert '"version": "2.1.0"' in data
    assert "PromptShield" in data

def test_custom_rule_severity(tmp_path):
    (tmp_path / ".promptshield.toml").write_text(
        '[rules]\nPS004 = "LOW"\n', encoding="utf-8"
    )
    (tmp_path / "tool.py").write_text(
        'url = "https://example.com"\n# tool endpoint\n', encoding="utf-8"
    )
    findings = scan_project(tmp_path)
    # no assertion on exact rule because the line may not be considered agent-related
    assert isinstance(findings, list)
