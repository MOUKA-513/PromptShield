from pathlib import Path
from .config import load_config
from .rules import scan_text, apply_rule_config

EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml",
    ".toml", ".md", ".txt", ".env", ".ini", ".cfg", ".xml"
}
IGNORED = {".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache", "node_modules", "dist", "build"}

def iter_files(root, config):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED for part in path.parts):
            continue
        relative = path.relative_to(root).as_posix()
        if any(relative == x or relative.startswith(x.rstrip("/") + "/") for x in config["ignore"]):
            continue
        if path.name == ".env" or path.suffix.lower() in EXTENSIONS:
            yield path

def scan_project(root):
    root = Path(root).resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    if not root.is_dir():
        raise NotADirectoryError(root)
    config = load_config(root)
    findings = []
    for path in iter_files(root, config):
        try:
            if path.stat().st_size > config["max_file_size"]:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = path.relative_to(root).as_posix()
        findings.extend(scan_text(text, relative))
    findings = apply_rule_config(findings, config["rules"])
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return sorted(findings, key=lambda x: (-rank[x.severity.value], x.file, x.line))
