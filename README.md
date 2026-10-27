# Automated Multi-Tool Penetration Testing and Security Assessment Tool

Lab-only security automation pipeline. Target goes in, recon → vulnerability
assessment → fuzzing/API testing runs automatically, a normalized report
comes out.

**Scope:** this tool is only to be run against targets in `config/allowlist.yaml`.
No target outside that list will be accepted by `TaskManager`, by design.
See `docs/ETHICS.md` (write this on Day 10) for the authorization policy.

## Architecture

```
1. Target Input ─▶ 2. Main Automation Engine ─▶ 3. Security Testing Modules ─▶ 4. Output/Reporting
                         │  TaskManager                3.1 Recon
                         │  ModuleOrchestrator          3.2 Vuln Assessment
                         │  ResultCollector              3.3 Web Fuzzing
                         │  WorkflowController            3.4 API Testing
                         ▼                                3.5 Exploitation (gated)
                    5. Data Storage   6. Logging & Monitoring   7. Target Env (lab only)
```

## Repo layout

```
core/       TaskManager, ModuleOrchestrator, ResultCollector, WorkflowController
modules/    One SecurityModule subclass per tool (nmap.py, nuclei.py, zap.py, ...)
config/     allowlist.yaml, scan_config.yaml
data/       scan results, JSON storage
logs/       execution logs, errors, scan status
reports/    generated HTML/PDF/CSV/JSON reports
tests/      unit tests
```

## Team module ownership

| Member | Owns |
|---|---|
| A | core/ (orchestration, scope gate, task manager) |
| B | modules/ recon + fuzzing (nmap, subfinder, httpx, amass, ffuf, gobuster) |
| C | modules/ vuln assessment + API testing (nuclei, zap, schemathesis, nikto) |
| D | modules/ exploitation (gated), data storage, logging, reports/ |

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Interface contract (read this before writing a module)

Every tool wrapper subclasses `core.security_module.SecurityModule` and
implements `run()`, `parse_output()`, `to_common_format()`. See
`core/security_module.py` for the contract and `core/result_format.py` for
the schema every module's output must conform to.

Orchestrator calls modules by `module.execute(target)`, which internally
calls the three methods above in order and always returns a list of
`Finding` objects — never raises on a tool-level failure, it returns an
error Finding instead, so one broken tool doesn't crash the pipeline.

### Quickstart: registering a real tool wrapper (Member B/C/D)

```python
# modules/nmap.py
import subprocess
from core.security_module import SecurityModule
from core.result_format import Finding, Severity

class NmapModule(SecurityModule):
    name = "nmap"
    module_category = "reconnaissance"   # or vulnerability_assessment /
                                          # web_fuzzing / api_testing / exploitation
    timeout_seconds = 120
    max_retries = 0                      # set >0 only if failures are usually transient
    requires_confirmation = False        # True only for exploitation-tier modules

    def run(self, target: str) -> str:
        result = subprocess.run(
            ["nmap", "-oX", "-", target],
            capture_output=True, text=True, timeout=self.timeout_seconds,
        )
        return result.stdout

    def parse_output(self, raw_output: str) -> list[dict]:
        ...  # parse XML -> list of plain dicts

    def to_common_format(self, target, parsed) -> list[Finding]:
        return [
            Finding(target=target, tool=self.name, module=self.module_category,
                     finding=f"Open port {p['port']}", severity=Severity.INFO,
                     evidence=str(p))
            for p in parsed
        ]
```

Wire it into the pipeline:

```python
from core.pipeline import ScanPipeline
from modules.nmap import NmapModule

pipeline = ScanPipeline()
pipeline.register_module(NmapModule())
# ... register your other modules here

record, report_path = pipeline.run("localhost:3000")
print(record.status)      # ScanStatus.COMPLETE / REJECTED / FAILED
print(report_path)        # data/<scan_id>.json — Common Result Format
```

### What's built (Days 1-5, Member A)

| Day | File | What it does |
|---|---|---|
| 1 | `core/result_format.py` | `Finding` / `Severity` / `FindingStatus` — the Common Result Format |
| 1 | `core/security_module.py` | `SecurityModule` abstract base class every tool wrapper implements |
| 1 | `core/task_manager.py` | `TaskManager` — target validation + the scope allowlist gate |
| 2 | `core/orchestrator.py` | `ModuleOrchestrator` — parallel/sequential module execution, error isolation |
| 3 | `core/workflow_controller.py` | `WorkflowController` — scan status tracking (queued/running/complete/failed/rejected) |
| 4 | `core/orchestrator.py` (retry) | Per-module retry with backoff for transient tool failures |
| 4 | `core/result_collector.py` | `ResultCollector` — merges + validates + saves the combined JSON report |
| 5 | `core/pipeline.py` | `ScanPipeline` — the single entry point wiring everything above together |
| 5 | `config/scan_config.yaml` | Default scan configuration, loaded via `ScanConfig.from_yaml()` |

37 tests, all passing (`python3 -m pytest tests/ -v`). Tests use stub
modules in `tests/stub_modules.py` standing in for Nmap/Nuclei/ZAP/etc. —
once B/C/D's real wrappers are registered, the same `ScanPipeline`,
`ModuleOrchestrator`, and `ResultCollector` work unchanged.
