"""
Stub modules standing in for Member B's recon tools and Member C's vuln
tools, until their real wrappers land in modules/. These exist purely to
prove the orchestrator's sequencing/parallel/error-isolation logic works
correctly — delete or ignore once real wrappers are registered instead.
"""

import time

from core.security_module import SecurityModule
from core.result_format import Finding, Severity


class StubReconModule(SecurityModule):
    name = "stub_recon"
    module_category = "reconnaissance"

    def run(self, target: str):
        time.sleep(0.05)  # simulate tool latency
        return {"open_ports": [80, 443]}

    def parse_output(self, raw_output):
        return [{"port": p} for p in raw_output["open_ports"]]

    def to_common_format(self, target, parsed):
        return [
            Finding(target=target, tool=self.name, module=self.module_category,
                    finding=f"Open port {p['port']}", severity=Severity.INFO, evidence=str(p))
            for p in parsed
        ]


class StubVulnModule(SecurityModule):
    name = "stub_vuln"
    module_category = "vulnerability_assessment"

    def run(self, target: str):
        time.sleep(0.05)
        return {"findings": [{"cve": "CVE-2021-TEST", "severity": "high"}]}

    def parse_output(self, raw_output):
        return raw_output["findings"]

    def to_common_format(self, target, parsed):
        sev_map = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
        return [
            Finding(target=target, tool=self.name, module=self.module_category,
                    finding=f"Vulnerable to {f['cve']}", severity=sev_map[f["severity"]],
                    evidence=str(f), cve=f["cve"])
            for f in parsed
        ]


class StubFuzzModule(SecurityModule):
    name = "stub_fuzz"
    module_category = "web_fuzzing"

    def run(self, target: str):
        time.sleep(0.05)
        return {"paths": ["/admin", "/backup"]}

    def parse_output(self, raw_output):
        return [{"path": p} for p in raw_output["paths"]]

    def to_common_format(self, target, parsed):
        return [
            Finding(target=target, tool=self.name, module=self.module_category,
                    finding=f"Discovered path {p['path']}", severity=Severity.LOW, evidence=str(p))
            for p in parsed
        ]


class StubBrokenModule(SecurityModule):
    """Simulates a tool crashing — proves one bad module doesn't kill the scan."""
    name = "stub_broken"
    module_category = "reconnaissance"

    def run(self, target: str):
        raise RuntimeError("simulated tool crash")

    def parse_output(self, raw_output):
        return []

    def to_common_format(self, target, parsed):
        return []


class StubFlakyModule(SecurityModule):
    """Fails its first N-1 calls, succeeds on the Nth — simulates a tool
    with transient failures (daemon warming up, brief network blip)."""
    name = "stub_flaky"
    module_category = "vulnerability_assessment"
    max_retries = 2  # allows up to 3 total attempts

    def __init__(self, fail_count: int = 2):
        self.fail_count = fail_count
        self.calls = 0

    def run(self, target: str):
        self.calls += 1
        if self.calls <= self.fail_count:
            raise RuntimeError(f"transient failure on attempt {self.calls}")
        return {"ok": True}

    def parse_output(self, raw_output):
        return [raw_output]

    def to_common_format(self, target, parsed):
        return [
            Finding(target=target, tool=self.name, module=self.module_category,
                    finding="Flaky tool succeeded", severity=Severity.INFO, evidence=str(parsed[0]))
        ]


class StubAlwaysFailsModule(SecurityModule):
    """Never succeeds — proves retry gives up after max_retries and the
    final result is still an error Finding, not an infinite loop."""
    name = "stub_always_fails"
    module_category = "vulnerability_assessment"
    max_retries = 1  # 2 total attempts

    def __init__(self):
        self.calls = 0

    def run(self, target: str):
        self.calls += 1
        raise RuntimeError("permanent failure")

    def parse_output(self, raw_output):
        return []

    def to_common_format(self, target, parsed):
        return []


class StubGatedExploitModule(SecurityModule):
    """Simulates a future Metasploit-style module — requires_confirmation=True
    means the orchestrator always runs it alone, sequentially, last."""
    name = "stub_exploit"
    module_category = "exploitation"
    requires_confirmation = True

    def run(self, target: str):
        time.sleep(0.02)
        return {"exploited": False, "reason": "stub — not a real exploit"}

    def parse_output(self, raw_output):
        return [raw_output]

    def to_common_format(self, target, parsed):
        return [
            Finding(target=target, tool=self.name, module=self.module_category,
                    finding="Exploit attempt (stub)", severity=Severity.INFO, evidence=str(parsed[0]))
        ]
