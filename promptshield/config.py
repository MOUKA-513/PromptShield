from pathlib import Path
import re

DEFAULT_RULES = {
    "PS001": "CRITICAL",
    "PS002": "HIGH",
    "PS003": "HIGH",
    "PS004": "MEDIUM",
    "PS005": "MEDIUM",
    "PS006": "HIGH",
    "PS007": "HIGH",
    "PS008": "MEDIUM",
    "PS009": "MEDIUM",
    "PS010": "CRITICAL",
}

def load_config(root: Path) -> dict:
    config = {"max_file_size": 1_000_000, "ignore": [], "rules": DEFAULT_RULES.copy()}
    path = root / ".promptshield.toml"
    if not path.exists():
        return config

    section = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" not in line:
            continue
        key, value = [x.strip() for x in line.split("=", 1)]
        value = value.strip('"')
        if section == "scanner" and key == "max_file_size":
            config["max_file_size"] = int(value)
        elif section == "ignore" and key == "paths":
            config["ignore"] = re.findall(r'"([^"]+)"', value)
        elif section == "rules" and key in config["rules"]:
            config["rules"][key] = value.upper()
    return config
