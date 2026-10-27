"""
SecurityModule — the interface every tool wrapper implements.

Member B, C, and D: your Nmap/Nuclei/ZAP/Metasploit wrappers all subclass
this. The orchestrator only ever calls `execute()` — it never knows or
cares whether the underlying tool is a subprocess call or an API client.

Minimal example subclass (this is what Day 1-2 should look like for a
simple CLI tool):

    class NmapModule(SecurityModule):
        name = "nmap"
        module_category = "reconnaissance"

        def run(self, target: str) -> str:
            result = subprocess.run(
                ["nmap", "-oX", "-", target],
                capture_output=True, text=True, timeout=120,
            )
            return result.stdout

        def parse_output(self, raw_output: str) -> list[dict]:
            # parse XML, return list of {"port":..., "service":..., ...}
            ...

        def to_common_format(self, target, parsed) -> list[Finding]:
            return [
                Finding(
                    target=target, tool=self.name, module=self.module_category,
                    finding=f"Open port {p['port']} ({p['service']})",
                    severity=Severity.INFO, evidence=str(p),
                )
                for p in parsed
            ]
"""

from abc import ABC, abstractmethod
from typing import Any
import logging

from core.result_format import Finding

logger = logging.getLogger("pentest.module")


class ModuleExecutionError(Exception):
    """Raised internally by a module; execute() catches this and converts
    it into an error Finding rather than letting it propagate."""


class SecurityModule(ABC):
    """
    Every concrete module (nmap.py, nuclei.py, zap.py, ...) subclasses this.

    Required class attributes on the subclass:
        name: str              -- e.g. "nmap"
        module_category: str   -- one of: "reconnaissance",
                                  "vulnerability_assessment", "web_fuzzing",
                                  "api_testing", "exploitation"
    """

    name: str = "unnamed_module"
    module_category: str = "uncategorized"
    timeout_seconds: int = 120
    requires_confirmation: bool = False  # True for exploitation-tier modules
    max_retries: int = 0  # how many times the orchestrator retries run() on
    # failure before giving up. Set >0 on tools prone to transient failures
    # (network timeouts against ZAP's daemon, a flaky scanner process) —
    # leave at 0 for tools where a failure is almost always deterministic
    # (bad args, target unreachable) and retrying wastes time.

    @abstractmethod
    def run(self, target: str) -> Any:
        """
        Actually invoke the tool (subprocess call or API call) and return
        its RAW output (string, dict, whatever the tool natively gives).
        Must respect self.timeout_seconds. Raise ModuleExecutionError on
        failure — do not let subprocess/requests exceptions escape raw.
        """
        raise NotImplementedError

    @abstractmethod
    def parse_output(self, raw_output: Any) -> list[dict]:
        """
        Turn the tool's raw output into a list of plain dicts describing
        each individual finding/result. No Finding objects yet — just
        parsed data.
        """
        raise NotImplementedError

    @abstractmethod
    def to_common_format(self, target: str, parsed: list[dict]) -> list[Finding]:
        """
        Map each parsed dict to a Finding in the Common Result Format,
        including the severity mapping for this tool's native scale.
        """
        raise NotImplementedError

    def execute(self, target: str) -> list[Finding]:
        """
        The only method the orchestrator calls. Runs run() -> parse_output()
        -> to_common_format() and NEVER raises — a broken tool returns a
        single error Finding instead of crashing the whole scan.
        """
        logger.info("module=%s target=%s status=starting", self.name, target)
        try:
            raw = self.run(target)
            parsed = self.parse_output(raw)
            findings = self.to_common_format(target, parsed)
            logger.info(
                "module=%s target=%s status=completed findings=%d",
                self.name, target, len(findings),
            )
            return findings
        except Exception as exc:  # noqa: BLE001 — intentional: isolate module failures
            logger.error(
                "module=%s target=%s status=failed error=%s",
                self.name, target, exc,
            )
            return [Finding.error(target, self.name, self.module_category, str(exc))]
