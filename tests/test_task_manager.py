"""
Day 1 tests for the scope gate. This is the one piece of the whole project
that MUST be provably correct before anyone (including Member D's future
exploitation module) builds on top of it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.task_manager import TaskManager, ScopeViolationError, TargetType


@pytest.fixture
def tm():
    return TaskManager()


def test_allowlisted_domain_is_accepted(tm):
    task = tm.create_task("localhost:3000")
    assert task.target == "localhost:3000"
    assert task.target_type == TargetType.DOMAIN


def test_random_internet_host_is_rejected(tm):
    with pytest.raises(ScopeViolationError):
        tm.create_task("google.com")


def test_ip_inside_allowlisted_range_is_accepted(tm):
    task = tm.create_task("192.168.56.50")
    assert task.target_type == TargetType.IP


def test_ip_outside_allowlisted_range_is_rejected(tm):
    with pytest.raises(ScopeViolationError):
        tm.create_task("10.0.0.1")


def test_target_type_detection_range():
    assert TaskManager.detect_target_type("192.168.56.0/24") == TargetType.RANGE


def test_target_type_detection_api_endpoint():
    assert TaskManager.detect_target_type("https://localhost:3000/api/v1") == TargetType.API_ENDPOINT


def test_empty_allowlist_rejects_everything(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("targets: []\n")
    tm = TaskManager(allowlist_path=empty)
    with pytest.raises(ScopeViolationError):
        tm.create_task("localhost:3000")


def test_missing_allowlist_file_rejects_everything(tmp_path):
    missing = tmp_path / "does_not_exist.yaml"
    tm = TaskManager(allowlist_path=missing)
    with pytest.raises(ScopeViolationError):
        tm.create_task("localhost:3000")
