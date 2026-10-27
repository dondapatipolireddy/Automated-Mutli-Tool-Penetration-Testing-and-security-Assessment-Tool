"""
Day 4 tests: ResultCollector merges, validates, and persists results
correctly, and catches a malformed Finding before it reaches storage.
"""

import json
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.orchestrator import ModuleOrchestrator
from core.result_collector import ResultCollector, ResultValidationError
from core.result_format import Finding, Severity
from core.task_manager import TaskManager, ScanConfig

from tests.stub_modules import StubReconModule, StubVulnModule, StubFuzzModule


@pytest.fixture
def orchestration_result():
    orch = ModuleOrchestrator()
    orch.register(StubReconModule())
    orch.register(StubVulnModule())
    orch.register(StubFuzzModule())
    task = TaskManager().create_task("localhost:3000")
    return orch.run(task)


def test_collect_produces_expected_summary(orchestration_result):
    collector = ResultCollector(data_dir=Path("/tmp/pentest_test_data_collect"))
    doc = collector.collect(orchestration_result, scan_id="test-scan-1")

    assert doc["scan_id"] == "test-scan-1"
    assert doc["target"] == "localhost:3000"
    assert doc["summary"]["total_findings"] == 5
    assert doc["summary"]["errors"] == 0
    assert doc["summary"]["by_severity"]["High"] == 1  # the stub CVE
    assert len(doc["modules_run"]) == 3


def test_collect_validates_finding_fields(orchestration_result):
    collector = ResultCollector(data_dir=Path("/tmp/pentest_test_data_collect"))
    doc = collector.collect(orchestration_result, scan_id="test-scan-2")

    for finding in doc["findings"]:
        for key in ("id", "target", "tool", "finding", "severity", "evidence", "timestamp", "status"):
            assert key in finding


def test_validate_raises_on_missing_field():
    collector = ResultCollector(data_dir=Path("/tmp/pentest_test_data_collect"))

    # simulate a module author breaking to_common_format() by hand-crafting
    # a dict and deleting a required key, since Finding itself can't be
    # constructed without them
    bad_finding = Finding(target="x", tool="broken_module", finding="f", severity=Severity.LOW, evidence="e")
    original_to_dict = bad_finding.to_dict
    bad_finding.to_dict = lambda: {k: v for k, v in original_to_dict().items() if k != "severity"}

    with pytest.raises(ResultValidationError):
        collector.validate([bad_finding])


def test_save_writes_file_with_correct_content(tmp_path, orchestration_result):
    collector = ResultCollector(data_dir=tmp_path)
    out_path = collector.save(orchestration_result, scan_id="test-scan-3")

    assert out_path.exists()
    assert out_path.name == "test-scan-3.json"

    with open(out_path) as f:
        saved = json.load(f)
    assert saved["summary"]["total_findings"] == 5


def test_save_without_scan_id_uses_timestamp(tmp_path, orchestration_result):
    collector = ResultCollector(data_dir=tmp_path)
    out_path = collector.save(orchestration_result)

    assert out_path.exists()
    assert out_path.suffix == ".json"
