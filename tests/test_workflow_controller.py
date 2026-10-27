"""
Day 3 tests: prove WorkflowController's status state machine is correct —
especially that scope rejection and tool-level errors are distinct from
a genuine controller failure.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.orchestrator import ModuleOrchestrator
from core.task_manager import TaskManager, ScanConfig
from core.workflow_controller import WorkflowController, ScanStatus, WorkflowError

from tests.stub_modules import StubReconModule, StubBrokenModule


@pytest.fixture
def controller():
    orch = ModuleOrchestrator()
    orch.register(StubReconModule())
    return WorkflowController(TaskManager(), orch)


def test_out_of_scope_target_is_rejected_not_failed(controller):
    record = controller.run_scan("google.com")
    assert record.status == ScanStatus.REJECTED
    assert record.error_message is not None
    assert record.result is None


def test_in_scope_target_completes(controller):
    record = controller.run_scan("localhost:3000")
    assert record.status == ScanStatus.COMPLETE
    assert record.result is not None
    assert len(record.result.all_findings) == 2  # stub recon: 2 open ports


def test_status_history_records_every_transition(controller):
    record = controller.run_scan("localhost:3000")
    statuses = [s for s, _ts in record.status_history]
    assert statuses == ["queued", "running", "complete"]


def test_rejected_scan_history_stops_at_rejected(controller):
    record = controller.run_scan("google.com")
    statuses = [s for s, _ts in record.status_history]
    assert statuses == ["queued", "rejected"]


def test_module_level_errors_still_complete_the_scan():
    orch = ModuleOrchestrator()
    orch.register(StubReconModule())
    orch.register(StubBrokenModule())
    controller = WorkflowController(TaskManager(), orch)

    record = controller.run_scan(
        "localhost:3000",
        config=ScanConfig(modules=["reconnaissance"]),
    )
    # a tool crashing is NOT the same as the scan failing
    assert record.status == ScanStatus.COMPLETE
    assert record.result.error_count == 1


def test_get_record_and_list_records(controller):
    r1 = controller.run_scan("localhost:3000")
    r2 = controller.run_scan("google.com")

    assert controller.get_record(r1.scan_id) is r1
    assert controller.get_record(r2.scan_id) is r2
    assert controller.get_record("nonexistent-id") is None
    assert len(controller.list_records()) == 2
