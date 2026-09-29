# 🛡️ PromptShield v1.0

**Security scanning for AI agents, prompts, tools, MCP-style configurations, and developer projects.**

PromptShield is a local-first static security analyzer. It scans source and configuration files, produces explainable findings, and can be used locally or in CI.

> Defensive tooling only. PromptShield performs static analysis and does not exploit targets.

## ✨ Features

- 🔑 Hard-coded secret detection
- 💉 Prompt-injection indicators
- 🧰 Dangerous agent/tool capability detection
- 🌐 Suspicious external endpoint detection
- 🔐 Weak authentication/configuration indicators
- 📦 MCP-style tool/manifest checks
- 📊 Security score
- 📄 JSON and HTML reports
- 🧾 SARIF output for code-scanning workflows
- ⚙️ Configurable rules and severity thresholds
- 🚦 CI failure gates
- 🧪 Test suite
- 🔄 GitHub Actions workflow
- 🧩 Example vulnerable and secure projects

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

promptshield scan examples/vulnerable-agent
```

Create an HTML report:

```bash
promptshield scan examples/vulnerable-agent --format html --output report.html
```

Create SARIF:

```bash
promptshield scan . --format sarif --output promptshield.sarif
```

Fail CI on high or critical findings:

```bash
promptshield scan . --fail-on HIGH
```

## Example

```text
╔══════════════════════════════════════════════╗
║              🛡️  PROMPTSHIELD                ║
║          AI SECURITY SCANNER v1.0             ║
╚══════════════════════════════════════════════╝

Target: examples/vulnerable-agent

Security score: 34/100

CRITICAL  2
HIGH      3
MEDIUM    2
LOW       0

2 critical findings require attention.
```

## Rule IDs

| ID | Category | Default severity |
|---|---|---|
| PS001 | Hard-coded secret | CRITICAL |
| PS002 | Prompt injection indicator | HIGH |
| PS003 | Dangerous tool capability | HIGH |
| PS004 | External endpoint | MEDIUM |
| PS005 | Secret in env file | MEDIUM |
| PS006 | Insecure HTTP endpoint | HIGH |
| PS007 | Wildcard tool permission | HIGH |
| PS008 | Missing tool confirmation | MEDIUM |
| PS009 | Excessive data access | MEDIUM |
| PS010 | Private-key material | CRITICAL |

## Configuration

Create `.promptshield.toml`:

```toml
[scanner]
max_file_size = 1000000

[ignore]
paths = ["tests/fixtures", "docs/generated"]

[rules]
PS004 = "LOW"
PS008 = "HIGH"
```

## CI

The repository includes a GitHub Actions workflow. A typical project can run:

```yaml
- name: PromptShield
  run: |
    pip install promptshield
    promptshield scan . --format sarif --output promptshield.sarif --fail-on HIGH
```

## Architecture

```text
Files
  │
  ▼
File discovery
  │
  ▼
Rule engine
  ├── Secrets
  ├── Prompts
  ├── Tools
  ├── Network
  ├── Permissions
  └── Data access
  │
  ▼
Findings
  │
  ├── Terminal
  ├── JSON
  ├── HTML
  └── SARIF
```

## Roadmap after v1.0

- AST-aware language rules
- More MCP-specific validation
- Baseline files
- Rule marketplace/plugin API
- IDE integration
- More ecosystem-specific detectors

## License

MIT
