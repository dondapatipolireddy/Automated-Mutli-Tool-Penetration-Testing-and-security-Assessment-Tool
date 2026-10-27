"""
ScanPipeline — the single entry point that wires TaskManager,
ModuleOrchestrator, WorkflowController, and ResultCollector together.
This is "2. Main Automation Engine" from the architecture diagram, as one
object a CLI, a future web UI, or a teammate's script can call without
knowing about the internal pieces.

Day 5 scope: ties everything built Day 1-4 into one callable pipeline,
proven with a full end-to-end test using stub modules standing in for
the real tool wrappers B/C/D will register.
"""

from __future__ import annotations

from pathlib import Path

from core.orchestrator import ModuleOrchestrator
from core.result_collector import ResultCollector
from core.security_module import SecurityModule
from core.task_manager import TaskManager, ScanConfig, ALLOWLIST_PATH
from core.workflow_controller import WorkflowController, ScanRecord

DEFAULT_SCAN_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "scan_config.yaml"


class ScanPipeline:
    """
    Usage:
        pipeline = ScanPipeline()
        pipeline.register_module(NmapModule())
        pipeline.register_module(NucleiModule())
        ...

        record, report_path = pipeline.run("localhost:3000")

    `record.status` tells you queued/running/complete/failed/rejected.
    `report_path` is where the Common Result Format JSON was saved (None
    if the scan was rejected before it ran).
    """

    def __init__(
        self,
        allowlist_path: Path = ALLOWLIST_PATH,
        data_dir: Path | None = None,
        max_parallel_workers: int = 4,
        retry_backoff_base: float = 1.0,
    ):
        self.task_manager = TaskManager(allowlist_path=allowlist_path)
        self.orchestrator = ModuleOrchestrator(
            max_parallel_workers=max_parallel_workers,
            retry_backoff_base=retry_backoff_base,
        )
        self.workflow = WorkflowController(self.task_manager, self.orchestrator)
        self.result_collector = ResultCollector(
            data_dir=data_dir or (Path(__file__).resolve().parent.parent / "data")
        )

    def register_module(self, module: SecurityModule) -> None:
        """Member B/C/D call this once per real tool wrapper at startup,
        e.g. pipeline.register_module(NmapModule())."""
        self.orchestrator.register(module)

    def run(
        self, target: str, config: ScanConfig | None = None
    ) -> tuple[ScanRecord, Path | None]:
        """
        Runs target input -> scope gate -> module orchestration -> result
        collection -> saved report, in one call. Returns the ScanRecord
        (status, findings, timing) and the path the JSON report was saved
        to (None if the scan never ran, i.e. REJECTED).
        """
        record = self.workflow.run_scan(target, config=config)

        report_path = None
        if record.result is not None:
            report_path = self.result_collector.save(record.result, scan_id=record.scan_id)

        return record, report_path

    @staticmethod
    def default_config() -> ScanConfig:
        if DEFAULT_SCAN_CONFIG_PATH.exists():
            return ScanConfig.from_yaml(DEFAULT_SCAN_CONFIG_PATH)
        return ScanConfig()
