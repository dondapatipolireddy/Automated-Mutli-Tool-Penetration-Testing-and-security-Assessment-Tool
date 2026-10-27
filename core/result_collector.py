"""
ResultCollector — merges an OrchestrationResult into one combined JSON
document matching the Common Result Format, validates it, and persists
it to data/ (step 5 in the architecture diagram).

This is what Member D's reporting code reads from, and what Member C's
severity-mapping logic feeds into. Nobody downstream should need to know
about ModuleRunResult or per-tool structure — just the flat findings list
this produces.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import json
import logging

from core.orchestrator import OrchestrationResult
from core.result_format import Finding

logger = logging.getLogger("pentest.result_collector")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Every Finding.to_dict() must contain exactly these keys — this is the
# schema contract from the architecture diagram's "Common Result Format"
# box. If a module's output is missing one of these, that's a bug in the
# module's to_common_format(), not something ResultCollector should
# silently paper over.
REQUIRED_FINDING_FIELDS = {
    "id", "target", "tool", "finding", "severity", "evidence", "timestamp", "status",
}


class ResultValidationError(Exception):
    """Raised when a Finding doesn't conform to the Common Result Format.
    This should only ever fire during development of a new module wrapper
    — it means to_common_format() is producing malformed output."""


class ResultCollector:
    def __init__(self, data_dir: Path = DATA_DIR):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def validate(self, findings: list[Finding]) -> None:
        for f in findings:
            d = f.to_dict()
            missing = REQUIRED_FINDING_FIELDS - d.keys()
            if missing:
                raise ResultValidationError(
                    f"Finding from tool={f.tool!r} is missing required field(s) "
                    f"{missing} — fix {f.tool}'s to_common_format()."
                )

    def collect(self, result: OrchestrationResult, scan_id: str | None = None) -> dict:
        """
        Builds the combined result document:
        {
          "scan_id": ...,
          "target": ...,
          "generated_at": ...,
          "summary": {"total_findings": N, "by_severity": {...}, "errors": N},
          "modules_run": [{"module": ..., "category": ..., "duration_seconds": ..., "attempts": ..., "finding_count": ...}],
          "findings": [ {Common Result Format dict}, ... ]
        }
        """
        self.validate(result.all_findings)

        by_severity: dict[str, int] = {}
        for f in result.all_findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

        return {
            "scan_id": scan_id,
            "target": result.target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(result.all_findings),
                "by_severity": by_severity,
                "errors": result.error_count,
            },
            "modules_run": [
                {
                    "module": r.module_name,
                    "category": r.category,
                    "duration_seconds": r.duration_seconds,
                    "attempts": r.attempts,
                    "finding_count": len(r.findings),
                }
                for r in result.module_results
            ],
            "findings": [f.to_dict() for f in result.all_findings],
        }

    def save(self, result: OrchestrationResult, scan_id: str | None = None) -> Path:
        """
        Writes the combined document to data/<scan_id or timestamp>.json
        and returns the path. This is the file Member D's report generator
        reads from.
        """
        document = self.collect(result, scan_id=scan_id)
        filename_id = scan_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = self.data_dir / f"{filename_id}.json"
        with open(out_path, "w") as f:
            json.dump(document, f, indent=2)
        logger.info("saved combined result to %s (%d findings)", out_path, document["summary"]["total_findings"])
        return out_path
