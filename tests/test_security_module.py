"""
Sanity test for the SecurityModule contract using a fake tool — confirms
the interface is actually usable before B/C/D build real wrappers against it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.security_module import SecurityModule
from core.result_format import Finding, Severity


class FakeOkModule(SecurityModule):
    name = "fake_ok_tool"
    module_category = "reconnaissance"

    def run(self, target: str) -> str:
        return '[{"port": 80, "service": "http"}]'

    def parse_output(self, raw_output: str) -> list[dict]:
        import json
        return json.loads(raw_output)

    def to_common_format(self, target: str, parsed: list[dict]) -> list[Finding]:
        return [
            Finding(
                target=target, tool=self.name, module=self.module_category,
                finding=f"Open port {p['port']}", severity=Severity.INFO,
                evidence=str(p),
            )
            for p in parsed
        ]


class FakeBrokenModule(SecurityModule):
    name = "fake_broken_tool"
    module_category = "reconnaissance"

    def run(self, target: str) -> str:
        raise RuntimeError("tool crashed")

    def parse_output(self, raw_output):
        return []

    def to_common_format(self, target, parsed):
        return []


def test_working_module_produces_findings():
    findings = FakeOkModule().execute("localhost:3000")
    assert len(findings) == 1
    assert findings[0].tool == "fake_ok_tool"
    assert findings[0].severity == Severity.INFO
    assert findings[0].status.value == "Unverified"


def test_broken_module_does_not_raise_and_returns_error_finding():
    findings = FakeBrokenModule().execute("localhost:3000")
    assert len(findings) == 1
    assert findings[0].status.value == "Error"
    assert "tool crashed" in findings[0].evidence


def test_finding_to_dict_matches_common_format_fields():
    f = Finding(target="x", tool="y", finding="z", severity=Severity.HIGH, evidence="e")
    d = f.to_dict()
    for key in ("id", "target", "tool", "finding", "severity", "evidence", "timestamp", "status"):
        assert key in d
