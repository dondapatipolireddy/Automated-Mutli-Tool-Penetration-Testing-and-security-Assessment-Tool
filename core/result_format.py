"""
Common Result Format — every module's output gets normalized into this shape.

This is the contract Member B, C, and D's tool wrappers all write to, and
what ResultCollector, Data Storage, and Reporting all read from. Nobody
changes this schema without telling the whole team, since everyone's code
depends on the field names matching exactly.
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


class Severity(str, Enum):
    """Unified severity scale. Each module maps its own tool's scale to this."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class FindingStatus(str, Enum):
    UNVERIFIED = "Unverified"
    CONFIRMED = "Confirmed"
    FALSE_POSITIVE = "False Positive"
    ERROR = "Error"  # the tool itself failed — not a real finding


@dataclass
class Finding:
    """
    One row in the Common Result Format. Matches the JSON shown in the
    architecture diagram:
    { "id", "target", "tool", "finding", "severity", "evidence", "timestamp", "status" }
    """
    target: str
    tool: str
    finding: str
    severity: Severity
    evidence: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    )
    status: FindingStatus = FindingStatus.UNVERIFIED
    module: Optional[str] = None       # e.g. "reconnaissance", "vulnerability_assessment"
    cve: Optional[str] = None
    raw_output_ref: Optional[str] = None  # path to the tool's raw output file, for audit

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d

    @staticmethod
    def error(target: str, tool: str, module: str, error_message: str) -> "Finding":
        """
        Used when a tool itself fails (timeout, crash, bad input) — so a
        broken tool produces a Finding the orchestrator can log and move
        past, instead of raising and killing the whole scan.
        """
        return Finding(
            target=target,
            tool=tool,
            finding="Module execution error",
            severity=Severity.INFO,
            evidence=error_message,
            status=FindingStatus.ERROR,
            module=module,
        )


# Severity mapping reference — each module owner maps their tool's native
# scale to this. Keep this table updated as new tools are added (Member C
# owns the authoritative version of this once vuln-assessment tools multiply).
SEVERITY_MAP_REFERENCE = {
    # Nuclei uses: info, low, medium, high, critical  (already matches)
    # ZAP uses: Informational, Low, Medium, High
    "Informational": Severity.INFO,
    # Nikto has no native severity — default to Low unless the finding text
    # matches a known high-risk pattern (module owner's judgment call)
}
