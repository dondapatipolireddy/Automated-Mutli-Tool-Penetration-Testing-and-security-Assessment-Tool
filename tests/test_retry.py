"""
Day 4 tests: prove the orchestrator's retry logic actually retries
transient failures and gives up correctly after max_retries.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.orchestrator import ModuleOrchestrator
from core.task_manager import TaskManager, ScanConfig

from tests.stub_modules import StubFlakyModule, StubAlwaysFailsModule


@pytest.fixture
def task_manager():
    return TaskManager()


def test_flaky_module_eventually_succeeds_via_retry(task_manager):
    orch = ModuleOrchestrator(retry_backoff_base=0.001)  # fast for tests
    flaky = StubFlakyModule(fail_count=2)  # fails twice, succeeds on 3rd
    orch.register(flaky)

    task = task_manager.create_task(
        "localhost:3000", config=ScanConfig(modules=["vulnerability_assessment"])
    )
    result = orch.run(task)

    assert result.error_count == 0
    assert flaky.calls == 3
    assert result.module_results[0].attempts == 3
    assert result.all_findings[0].finding == "Flaky tool succeeded"


def test_always_failing_module_gives_up_after_max_retries(task_manager):
    orch = ModuleOrchestrator(retry_backoff_base=0.001)
    broken = StubAlwaysFailsModule()  # max_retries=1 -> 2 total attempts
    orch.register(broken)

    task = task_manager.create_task(
        "localhost:3000", config=ScanConfig(modules=["vulnerability_assessment"])
    )
    result = orch.run(task)

    assert broken.calls == 2  # initial attempt + 1 retry, then stop
    assert result.error_count == 1
    assert result.module_results[0].attempts == 2


def test_module_with_zero_max_retries_only_tries_once(task_manager):
    from tests.stub_modules import StubBrokenModule
    orch = ModuleOrchestrator(retry_backoff_base=0.001)
    broken = StubBrokenModule()  # max_retries=0 by default
    orch.register(broken)

    task = task_manager.create_task(
        "localhost:3000", config=ScanConfig(modules=["reconnaissance"])
    )
    result = orch.run(task)

    assert result.module_results[0].attempts == 1
