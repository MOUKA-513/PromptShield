from dataclasses import dataclass
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

WEIGHT = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 18,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    recommendation: str
    file: str
    line: int
    evidence: str

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "recommendation": self.recommendation,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence[:300],
        }
