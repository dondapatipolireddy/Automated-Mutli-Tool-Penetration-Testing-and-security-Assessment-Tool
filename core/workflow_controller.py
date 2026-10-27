"""
WorkflowController — owns scan-level status tracking and exception
handling around a full scan run. This is the piece that lets anyone
(a UI, a CLI, a teammate's report module) ask "what's happening with
scan X" without re-reading logs.

Day 3 scope: status state machine + the run() wrapper that drives
TaskManager -> ModuleOrchestrator and records status transitions.
Day 4 adds retry; Day 5 wires this into a full pipeline test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
import uuid

from core.orchestrator import ModuleOrchestrator, OrchestrationResult
from core.task_manager import TaskManager, ScanConfig, ScopeViolationError

logger = logging.getLogger("pentest.workflow")


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    FAILED = "failed"
    COMPLETE = "complete"
    REJECTED = "rejected"  # scope violation — never even started


class WorkflowError(Exception):
    """Wraps any unexpected exception raised during a scan run, so callers
    get one exception type to catch regardless of what went wrong inside."""


@dataclass
class ScanRecord:
    """
    The thing a UI/CLI/report would poll or read. One per scan attempt.
    status_history lets you see exactly when each transition happened,
    which matters for the activity-log / performance-metrics requirement
    from the architecture diagram's Logging & Monitoring module.
    """
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    status: ScanStatus = ScanStatus.QUEUED
    status_history: list[tuple[str, str]] = field(default_factory=list)  # (status, iso_timestamp)
    error_message: str | None = None
    result: OrchestrationResult | None = None

    def _transition(self, new_status: ScanStatus) -> None:
        self.status = new_status
        self.status_history.append((new_status.value, datetime.now(timezone.utc).isoformat()))
        logger.info("scan_id=%s target=%s status=%s", self.scan_id, self.target, new_status.value)


class WorkflowController:
    """
    Usage:
        wc = WorkflowController(task_manager, orchestrator)
        record = wc.run_scan("localhost:3000", config=ScanConfig(...))
        record.status            # ScanStatus.COMPLETE / FAILED / REJECTED
        record.result.all_findings

    Every call to run_scan() returns a ScanRecord — it never raises for
    expected failure modes (scope rejection, module errors). It only
    raises WorkflowError for something genuinely unexpected (a bug in the
    controller itself), which should be rare and worth investigating.
    """

    def __init__(self, task_manager: TaskManager, orchestrator: ModuleOrchestrator):
        self.task_manager = task_manager
        self.orchestrator = orchestrator
        self._records: dict[str, ScanRecord] = {}

    def run_scan(self, target: str, config: ScanConfig | None = None) -> ScanRecord:
        record = ScanRecord(target=target)
        self._records[record.scan_id] = record
        record._transition(ScanStatus.QUEUED)

        try:
            task = self.task_manager.create_task(target, config=config)
        except ScopeViolationError as exc:
            record.error_message = str(exc)
            record._transition(ScanStatus.REJECTED)
            return record

        record._transition(ScanStatus.RUNNING)

        try:
            result = self.orchestrator.run(task)
        except Exception as exc:  # noqa: BLE001 — orchestrator itself should not raise,
            # but if it does (a bug, not a tool failure — those are already
            # caught inside SecurityModule.execute), the scan is marked
            # failed rather than crashing whatever called run_scan().
            record.error_message = str(exc)
            record._transition(ScanStatus.FAILED)
            logger.error("scan_id=%s unexpected orchestrator failure: %s", record.scan_id, exc)
            raise WorkflowError(f"Scan {record.scan_id} failed unexpectedly: {exc}") from exc

        record.result = result
        # a scan where every module errored is still "complete" (we tried
        # everything we were asked to) rather than "failed" — FAILED is
        # reserved for controller-level bugs, not tool-level errors
        record._transition(ScanStatus.COMPLETE)
        return record

    def get_record(self, scan_id: str) -> ScanRecord | None:
        return self._records.get(scan_id)

    def list_records(self) -> list[ScanRecord]:
        return list(self._records.values())
