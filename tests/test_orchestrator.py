"""
Day 2 tests: prove ModuleOrchestrator correctly sequences/parallelizes
modules, isolates failures, and respects which categories a scan config
asked for — using stub modules standing in for the real tool wrappers.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.orchestrator import ModuleOrchestrator
from core.task_manager import TaskManager, ScanConfig

from tests.stub_modules import (
    StubReconModule, StubVulnModule, StubFuzzModule,
    StubBrokenModule, StubGatedExploitModule,
)


@pytest.fixture
def task_manager():
    return TaskManager()


@pytest.fixture
def full_orchestrator():
    orch = ModuleOrchestrator()
    orch.register(StubReconModule())
    orch.register(StubVulnModule())
    orch.register(StubFuzzModule())
    return orch


def test_runs_all_registered_modules_for_default_config(task_manager, full_orchestrator):
    task = task_manager.create_task("localhost:3000")  # default config = recon+vuln+fuzz
    result = full_orchestrator.run(task)

    module_names = {r.module_name for r in result.module_results}
    assert module_names == {"stub_recon", "stub_vuln", "stub_fuzz"}


def test_only_runs_modules_in_requested_categories(task_manager, full_orchestrator):
    task = task_manager.create_task(
        "localhost:3000",
        config=ScanConfig(modules=["reconnaissance"]),
    )
    result = full_orchestrator.run(task)

    assert len(result.module_results) == 1
    assert result.module_results[0].module_name == "stub_recon"


def test_findings_are_aggregated_across_modules(task_manager, full_orchestrator):
    task = task_manager.create_task("localhost:3000")
    result = full_orchestrator.run(task)

    assert len(result.all_findings) == 5  # 2 ports + 1 cve + 2 paths
    assert result.error_count == 0


def test_broken_module_does_not_stop_other_modules(task_manager):
    orch = ModuleOrchestrator()
    orch.register(StubReconModule())
    orch.register(StubBrokenModule())  # also "reconnaissance" category
    orch.register(StubVulnModule())

    task = task_manager.create_task(
        "localhost:3000",
        config=ScanConfig(modules=["reconnaissance", "vulnerability_assessment"]),
    )
    result = orch.run(task)

    # all three modules ran despite one crashing
    assert len(result.module_results) == 3
    assert result.error_count == 1
    # the good modules' findings are still present
    good_tools = {f.tool for f in result.all_findings if f.status.value != "Error"}
    assert good_tools == {"stub_recon", "stub_vuln"}


def test_gated_exploitation_module_runs_sequentially_and_last(task_manager):
    orch = ModuleOrchestrator()
    orch.register(StubReconModule())
    orch.register(StubGatedExploitModule())

    task = task_manager.create_task(
        "localhost:3000",
        config=ScanConfig(modules=["reconnaissance", "exploitation"]),
    )
    result = orch.run(task)

    module_names = [r.module_name for r in result.module_results]
    assert module_names[-1] == "stub_exploit"  # sequential batch always runs after parallel batch


def test_no_modules_selected_returns_empty_result_not_error(task_manager, full_orchestrator):
    task = task_manager.create_task(
        "localhost:3000",
        config=ScanConfig(modules=["api_testing"]),  # nothing registered for this category
    )
    result = full_orchestrator.run(task)

    assert result.module_results == []
    assert result.all_findings == []
