"""
Day 5 integration tests: the full pipeline, target input to saved report,
exercised end-to-end exactly as a teammate or future CLI would call it.
Uses stub modules standing in for B/C/D's real tool wrappers — these
tests should keep passing unchanged once real wrappers replace the stubs,
since they only depend on the SecurityModule contract.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.pipeline import ScanPipeline
from core.task_manager import ScanConfig
from core.workflow_controller import ScanStatus

from tests.stub_modules import (
    StubReconModule, StubVulnModule, StubFuzzModule,
    StubBrokenModule, StubGatedExploitModule,
)


@pytest.fixture
def pipeline(tmp_path):
    p = ScanPipeline(data_dir=tmp_path, retry_backoff_base=0.001)
    p.register_module(StubReconModule())
    p.register_module(StubVulnModule())
    p.register_module(StubFuzzModule())
    return p


def test_full_pipeline_end_to_end_against_allowlisted_target(pipeline):
    record, report_path = pipeline.run("localhost:3000")

    assert record.status == ScanStatus.COMPLETE
    assert report_path is not None
    assert report_path.exists()

    with open(report_path) as f:
        report = json.load(f)

    assert report["target"] == "localhost:3000"
    assert report["scan_id"] == record.scan_id
    assert report["summary"]["total_findings"] == 5
    assert report["summary"]["errors"] == 0
    assert len(report["modules_run"]) == 3
    # every finding in the saved report matches the Common Result Format
    for finding in report["findings"]:
        for key in ("id", "target", "tool", "finding", "severity", "evidence", "timestamp", "status"):
            assert key in finding


def test_full_pipeline_rejects_out_of_scope_target_before_running_anything(pipeline):
    record, report_path = pipeline.run("google.com")

    assert record.status == ScanStatus.REJECTED
    assert report_path is None
    # no JSON file should have been written for a rejected scan
    assert list(pipeline.result_collector.data_dir.glob("*.json")) == []


def test_full_pipeline_respects_requested_module_subset(pipeline):
    record, report_path = pipeline.run(
        "localhost:3000", config=ScanConfig(modules=["reconnaissance"])
    )
    with open(report_path) as f:
        report = json.load(f)

    assert len(report["modules_run"]) == 1
    assert report["modules_run"][0]["module"] == "stub_recon"


def test_full_pipeline_with_a_broken_module_still_completes_and_reports_the_error(tmp_path):
    pipeline = ScanPipeline(data_dir=tmp_path, retry_backoff_base=0.001)
    pipeline.register_module(StubReconModule())
    pipeline.register_module(StubBrokenModule())

    record, report_path = pipeline.run(
        "localhost:3000", config=ScanConfig(modules=["reconnaissance"])
    )

    assert record.status == ScanStatus.COMPLETE  # tool failure != scan failure
    with open(report_path) as f:
        report = json.load(f)
    assert report["summary"]["errors"] == 1
    error_findings = [f for f in report["findings"] if f["status"] == "Error"]
    assert len(error_findings) == 1
    assert error_findings[0]["tool"] == "stub_broken"


def test_full_pipeline_runs_gated_exploitation_module_last_and_sequentially(tmp_path):
    pipeline = ScanPipeline(data_dir=tmp_path, retry_backoff_base=0.001)
    pipeline.register_module(StubReconModule())
    pipeline.register_module(StubGatedExploitModule())

    record, report_path = pipeline.run(
        "localhost:3000",
        config=ScanConfig(modules=["reconnaissance", "exploitation"]),
    )
    with open(report_path) as f:
        report = json.load(f)

    module_order = [m["module"] for m in report["modules_run"]]
    assert module_order[-1] == "stub_exploit"


def test_default_config_loads_from_yaml_file():
    config = ScanPipeline.default_config()
    assert "reconnaissance" in config.modules
    assert config.output_format == "json"
