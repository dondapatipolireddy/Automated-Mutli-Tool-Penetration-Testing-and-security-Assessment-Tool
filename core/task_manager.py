"""
TaskManager — handles target input, scan configuration, and the scope
allowlist gate.

This is the front door of the whole pipeline. Nothing downstream (recon,
vuln assessment, exploitation) runs against a target that hasn't passed
validate_target() here. That's a deliberate single choke point rather
than scattering scope checks across modules.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
import ipaddress
import logging
import re

import yaml

logger = logging.getLogger("pentest.task_manager")

ALLOWLIST_PATH = Path(__file__).resolve().parent.parent / "config" / "allowlist.yaml"


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    RANGE = "range"
    API_ENDPOINT = "api_endpoint"


class ScopeViolationError(Exception):
    """Raised when a target is not in the allowlist. This should be the
    ONLY way a target gets rejected — callers should catch this and stop,
    never retry or widen scope automatically."""


@dataclass
class ScanConfig:
    modules: list[str] = field(default_factory=lambda: [
        "reconnaissance", "vulnerability_assessment", "web_fuzzing",
    ])
    output_format: str = "json"
    scheduling: Optional[str] = None  # e.g. "immediate" or a cron-like string

    @classmethod
    def from_yaml(cls, path: Path) -> "ScanConfig":
        """Load a ScanConfig from config/scan_config.yaml or similar. Falls
        back to defaults for any field the file doesn't specify."""
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(
            modules=data.get("modules", cls().modules),
            output_format=data.get("output_format", "json"),
            scheduling=data.get("scheduling"),
        )


@dataclass
class ScanTask:
    target: str
    target_type: TargetType
    config: ScanConfig
    requested_by: str = "local_user"


class TaskManager:
    """
    Entry point: TaskManager(...).create_task(target, target_type) returns
    a ScanTask only if the target passes the allowlist check. Everything
    else (ModuleOrchestrator, etc.) should assume any ScanTask it receives
    is already authorized — they don't need to re-check scope.
    """

    def __init__(self, allowlist_path: Path = ALLOWLIST_PATH):
        self.allowlist_path = allowlist_path
        self._allowlist = self._load_allowlist()

    def _load_allowlist(self) -> list[dict]:
        if not self.allowlist_path.exists():
            logger.warning("allowlist file not found at %s — ALL targets will be rejected", self.allowlist_path)
            return []
        with open(self.allowlist_path) as f:
            data = yaml.safe_load(f) or {}
        return data.get("targets", [])

    def reload_allowlist(self) -> None:
        """Call this if allowlist.yaml changes mid-session rather than
        restarting the process."""
        self._allowlist = self._load_allowlist()

    # ---- target type detection --------------------------------------

    @staticmethod
    def detect_target_type(target: str) -> TargetType:
        target = target.strip()
        if "/" in target and re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", target):
            return TargetType.RANGE
        try:
            ipaddress.ip_address(target.split(":")[0])
            return TargetType.IP
        except ValueError:
            pass
        if target.startswith("http://") or target.startswith("https://"):
            if "/api" in target or target.rstrip("/").endswith((".json", "/v1", "/v2")):
                return TargetType.API_ENDPOINT
        return TargetType.DOMAIN

    # ---- scope gate ----------------------------------------------------

    def validate_target(self, target: str) -> bool:
        """
        Returns True only if `target` matches an allowlist entry exactly,
        or falls inside an allowlisted CIDR range. No partial matches, no
        wildcard domains, no "close enough" — ambiguous input is rejected,
        not interpreted charitably.
        """
        target_clean = target.strip().lower()

        for entry in self._allowlist:
            entry_value = str(entry.get("value", "")).lower()
            entry_type = entry.get("type")

            if entry_type == "range":
                if self._ip_in_range(target_clean, entry_value):
                    return True
            else:
                # exact match on domain/host[:port] or ip
                if target_clean == entry_value:
                    return True
                # allow matching host without an explicit port against an
                # allowlist entry that specifies one, and vice versa
                if target_clean.split(":")[0] == entry_value.split(":")[0] and (
                    ":" not in target_clean or ":" not in entry_value
                ):
                    return True

        return False

    @staticmethod
    def _ip_in_range(ip_str: str, cidr: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str.split(":")[0])
            network = ipaddress.ip_network(cidr, strict=False)
            return ip in network
        except ValueError:
            return False

    # ---- task creation ---------------------------------------------------

    def create_task(
        self, target: str, config: Optional[ScanConfig] = None
    ) -> ScanTask:
        """
        The single entry point for starting a scan. Raises
        ScopeViolationError if the target isn't authorized — callers must
        not catch-and-proceed on that exception.
        """
        if not self.validate_target(target):
            logger.error("SCOPE VIOLATION: rejected target=%s", target)
            raise ScopeViolationError(
                f"Target '{target}' is not in the authorized allowlist "
                f"({self.allowlist_path}). Add it there with explicit "
                f"authorization before scanning it."
            )

        target_type = self.detect_target_type(target)
        logger.info("task created: target=%s type=%s", target, target_type.value)
        return ScanTask(
            target=target,
            target_type=target_type,
            config=config or ScanConfig(),
        )
