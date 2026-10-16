"""A failed real-service run must never satisfy final acceptance gates."""
from __future__ import annotations

import hashlib

import pytest

from evals.datasets.dedale import audit
from evals.tests.test_dedale_audit import runtime_fixture


def live_fixture(tmp_path, monkeypatch):
    report = runtime_fixture(tmp_path)
    monkeypatch.setattr(audit, "ROOT", tmp_path)
    events, raw = tmp_path / "events.jsonl", tmp_path / "raw.jsonl"
    events.write_bytes(b'{"message":"normal calibration"}\n')
    raw.write_bytes(b'{"message":"original normal event"}\n')
    event_hash = hashlib.sha256(events.read_bytes()).hexdigest()
    report.update(status="passed", live_acceptance_passed=True, model_invocations=0,
                  input_sha256=event_hash, original_input_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),
                  content_hashes={"event": event_hash})
    report["runtime_artifacts"]["agent_events_sha256"] = event_hash
    report["checks"] = {name: {"status": "passed"} for name in (
        "source_projection", "duplicate_import", "get_alert_context", "search_security_events",
        "mcp_negative_probes", "half_open_window", "real_service_chain", "isolated_resource_cleanup",
        "container_cleanup",
    )}
    report["checks"]["scoring_filesystem_isolation"] = {
        "status": "passed", "host_scoring_canary_exists": True,
        "same_process_probe": {"agent_readable": True, "pid": 1, "nonce": "owned-calibration",
            "hostname": "owned-container", "agent_sha256": event_hash,
            "forbidden_reads": [{"readable": False, "error_type": "PermissionError"} for _ in range(5)]},
        "container_inspection": {"hostname": "owned-container", "container_id": "owned-container-full-id",
            "root_read_only": True, "privileged": False, "capabilities_dropped": ["ALL"],
            "no_new_privileges": True, "private_pid_namespace": True, "user": "65532:65532",
            "mounts": [{"target": name, "read_only": True} for name in (
                "/app/agent", "/app/backend/src", "/app/runtime.py", "/opt/dedale-deps")]},
    }
    return report, events, raw


def test_complete_successful_live_report_satisfies_both_gates(tmp_path, monkeypatch):
    report, events, raw = live_fixture(tmp_path, monkeypatch)
    assert audit._live_checks(report, events_path=events, raw_events_path=raw) == (True, True)


@pytest.mark.parametrize("change", [
    "failed_report", "pending_report", "missing_acceptance", "failed_cleanup",
    "pending_cleanup", "failed_execution", "extra_failed_check",
])
def test_incomplete_or_failed_live_run_cannot_be_accepted(tmp_path, monkeypatch, change):
    report, events, raw = live_fixture(tmp_path, monkeypatch)
    if change == "failed_report":
        report.update(status="failed", live_acceptance_passed=False)
    elif change == "pending_report":
        report["status"] = "pending"
    elif change == "missing_acceptance":
        report.pop("live_acceptance_passed")
    elif change in {"failed_cleanup", "pending_cleanup"}:
        report["checks"]["container_cleanup"]["status"] = "failed" if change == "failed_cleanup" else "pending"
    elif change == "failed_execution":
        report["checks"]["execution"] = {"status": "failed", "error_type": "RuntimeError"}
    else:
        report["checks"]["additional_required_probe"] = {"status": "failed"}
    assert audit._live_checks(report, events_path=events, raw_events_path=raw) == (False, False)
