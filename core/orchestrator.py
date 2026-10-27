"""
ModuleOrchestrator — runs the registered SecurityModules for a ScanTask,
in sequence or in parallel depending on scan config, and hands everything
back as a flat list of Findings.

Day 2 scope: the orchestrator itself, proven against stub modules. Real
Nmap/Nuclei/ZAP/etc. wrappers (Member B/C/D) register into the same
MODULE_REGISTRY below once they exist — the orchestrator doesn't change.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import logging
import time

from core.result_format import Finding
from core.security_module import SecurityModule
from core.task_manager import ScanTask

logger = logging.getLogger("pentest.orchestrator")

# Which module categories are safe to run in parallel against the same
# target. Exploitation is deliberately excluded — even once Member D wires
# Metasploit in, it always runs alone, sequentially, after everything else.
PARALLEL_SAFE_CATEGORIES = {
    "reconnaissance", "vulnerability_assessment", "web_fuzzing", "api_testing",
}


@dataclass
class ModuleRunResult:
    module_name: str
    category: str
    findings: list[Finding]
    duration_seconds: float
    attempts: int = 1


@dataclass
class OrchestrationResult:
    target: str
    module_results: list[ModuleRunResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        return [f for r in self.module_results for f in r.findings]

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.all_findings if f.status.value == "Error")


class ModuleOrchestrator:
    """
    Usage:
        orch = ModuleOrchestrator()
        orch.register(NmapModule())
        orch.register(NucleiModule())
        result = orch.run(scan_task)

    Modules are registered by instance, not by class — this lets each
    module be configured (timeouts, API keys, etc.) before registration
    without the orchestrator knowing about any of that.
    """

    def __init__(self, max_parallel_workers: int = 4, retry_backoff_base: float = 1.0):
        self._modules: list[SecurityModule] = []
        self.max_parallel_workers = max_parallel_workers
        # base seconds for retry backoff (1s, 2s, 4s, ... capped at 10s).
        # Tests pass a tiny value so retry tests run instantly.
        self.retry_backoff_base = retry_backoff_base

    def register(self, module: SecurityModule) -> None:
        self._modules.append(module)
        logger.info("registered module=%s category=%s", module.name, module.module_category)

    def modules_for_task(self, task: ScanTask) -> list[SecurityModule]:
        """Only run modules whose category is in task.config.modules."""
        wanted = set(task.config.modules)
        return [m for m in self._modules if m.module_category in wanted]

    def run(self, task: ScanTask) -> OrchestrationResult:
        """
        Splits the selected modules into a parallel-safe batch and a
        sequential batch (anything requiring confirmation, e.g. future
        exploitation modules, or any category not in PARALLEL_SAFE_CATEGORIES),
        runs the parallel batch concurrently, then the sequential batch
        one at a time.
        """
        selected = self.modules_for_task(task)
        if not selected:
            logger.warning("no modules selected for target=%s config=%s", task.target, task.config.modules)
            return OrchestrationResult(target=task.target)

        parallel_batch = [
            m for m in selected
            if m.module_category in PARALLEL_SAFE_CATEGORIES and not m.requires_confirmation
        ]
        sequential_batch = [m for m in selected if m not in parallel_batch]

        result = OrchestrationResult(target=task.target)

        if parallel_batch:
            result.module_results.extend(self._run_parallel(parallel_batch, task.target))

        for module in sequential_batch:
            result.module_results.append(self._run_one(module, task.target))

        logger.info(
            "orchestration complete: target=%s modules_run=%d findings=%d errors=%d",
            task.target, len(result.module_results), len(result.all_findings), result.error_count,
        )
        return result

    def _run_one(self, module: SecurityModule, target: str) -> ModuleRunResult:
        """
        Runs module.execute() and retries up to module.max_retries times
        if the attempt produced only error Findings (i.e. the tool itself
        failed, not "ran fine and found nothing"). A short backoff between
        attempts gives transient failures (daemon not ready yet, brief
        network blip) a chance to clear. The LAST attempt's result is
        always what's kept, whether it succeeded or not.
        """
        start = time.monotonic()
        attempts = 0
        findings: list[Finding] = []

        while True:
            attempts += 1
            findings = module.execute(target)
            attempt_failed = bool(findings) and all(f.status.value == "Error" for f in findings)

            if not attempt_failed or attempts > module.max_retries:
                break

            backoff = min(self.retry_backoff_base * (2 ** (attempts - 1)), 10)
            logger.warning(
                "module=%s target=%s attempt=%d failed, retrying in %ds (max_retries=%d)",
                module.name, target, attempts, backoff, module.max_retries,
            )
            time.sleep(backoff)

        duration = time.monotonic() - start
        return ModuleRunResult(
            module_name=module.name,
            category=module.module_category,
            findings=findings,
            duration_seconds=round(duration, 3),
            attempts=attempts,
        )

    def _run_parallel(self, modules: list[SecurityModule], target: str) -> list[ModuleRunResult]:
        results: list[ModuleRunResult] = []
        with ThreadPoolExecutor(max_workers=self.max_parallel_workers) as pool:
            future_to_module = {
                pool.submit(self._run_one, m, target): m for m in modules
            }
            for future in as_completed(future_to_module):
                module = future_to_module[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001 — a thread-level crash, not a tool-level one
                    logger.error("module=%s crashed outside execute(): %s", module.name, exc)
                    results.append(ModuleRunResult(
                        module_name=module.name,
                        category=module.module_category,
                        findings=[Finding.error(target, module.name, module.module_category, str(exc))],
                        duration_seconds=0.0,
                    ))
        return results
