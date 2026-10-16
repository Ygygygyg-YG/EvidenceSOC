"""Fail-closed contracts for the live DEDALE calibration acceptance harness."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/dedale_task12_live_check.py"


def harness():
    assert SCRIPT.is_file(), "DEDALE live acceptance harness is missing"
    spec = importlib.util.spec_from_file_location("dedale_live_check", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def event(at="2025-01-05T21:00:07.056Z", *, host="dmzserver"):
    return {
        "dataset_id": "dedale-v2.1",
        "external_id": "dedale-1",
        "source": "auditbeat",
        "event_type": "process",
        "observed_at": at,
        "host": host,
        "message": "process executable=/usr/lib/dovecot/auth command=/usr/sbin/dovecot",
        "provenance": {"raw_sha256": "a" * 64},
    }


def test_selects_one_host_and_half_open_window_without_mutating_original():
    module = harness()
    rows = [event(), event("2025-01-05T21:30:00Z"), event(host="another")]
    selected, scope = module.select_calibration_events(rows, case_id="case-001")
    assert len(selected) == 1
    assert scope.time_from == datetime(2025, 1, 5, 21, tzinfo=UTC)
    assert scope.time_to - scope.time_from == timedelta(minutes=30)
    assert scope.created_at == datetime(2025, 1, 5, 21, 15, tzinfo=UTC)
    assert selected[0]["dataset_id"] == "dedale-v2.1:case-001"
    assert rows[0]["dataset_id"] == "dedale-v2.1"
    assert selected[0]["provenance"] == rows[0]["provenance"]


@pytest.mark.parametrize(
    "change",
    [
        {"case_id": "another"},
        {"dataset_id": "dedale-v2.1:another"},
        {"index_name": "security-events-v1"},
        {"time_from": "2025-01-05T20:59:59Z"},
        {"time_to": "2025-01-05T21:30:01Z"},
    ],
)
def test_request_scope_rejects_other_cases_datasets_indices_and_time_escape(change):
    module = harness()
    _, scope = module.select_calibration_events([event()], case_id="case-001")
    arguments = {
        "case_id": scope.case_id,
        "dataset_id": scope.dataset_id,
        "index_name": scope.index_name,
        "time_from": scope.time_from.isoformat(),
        "time_to": scope.time_to.isoformat(),
    }
    arguments.update(change)
    with pytest.raises(ValueError, match="scope"):
        scope.validate_request(**arguments)


def test_source_dataset_mismatch_and_answer_fields_fail_closed():
    module = harness()
    for bad in ({**event(), "dataset_id": "ait"}, {**event(), "is_attack": False}):
        with pytest.raises(ValueError):
            module.select_calibration_events([bad], case_id="case-001")


def test_fixture_settings_ignore_dotenv_and_model_secrets(monkeypatch):
    module = harness()
    monkeypatch.setenv("LLM_MODE", "deepseek")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "should-not-be-read")
    settings = module.fixture_settings()
    assert settings.llm_mode == "fixture"
    assert settings.deepseek_api_key is None


def test_pending_filesystem_isolation_cannot_be_reported_as_acceptance_pass(tmp_path):
    module = harness()
    report = module.new_report()
    report["checks"]["real_service_chain"] = {"status": "passed"}
    module.finalize_report(report, tmp_path / "report.json")
    saved = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert saved["status"] == "pending"
    assert saved["freeze_eligible"] is False
    assert saved["checks"]["scoring_filesystem_isolation"]["status"] == "pending"
    assert (
        "working directory" in saved["checks"]["scoring_filesystem_isolation"]["reason"]
    )


def test_missing_input_still_writes_failed_report_and_returns_nonzero(tmp_path):
    module = harness()
    output = tmp_path / "report.json"
    assert (
        module.main(
            ["--events", str(tmp_path / "missing.jsonl"), "--output", str(output)]
        )
        != 0
    )
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["status"] == "failed"
    assert saved["freeze_eligible"] is False


def test_original_bytes_and_allowed_projection_must_both_match():
    module = harness()
    from evals.datasets.dedale.parse import parse_event

    original = b'{"@timestamp":"2025-01-05T21:00:07.056Z","host":{"name":"dmzserver"},"process":{"executable":"/usr/lib/dovecot/auth","title":"/usr/sbin/dovecot"}}\n'
    parsed = parse_event(
        original,
        archive="system_logs_auditbeat.zip",
        relative_log_path="daily_auditbeat/example.jsonl.bz2",
        line_number=1,
    )
    selected, _ = module.select_calibration_events([parsed], case_id="case-001")
    assert module.verify_source_projection(selected, [original]) == 1
    with pytest.raises(ValueError):
        module.verify_source_projection(selected, [original.rstrip(b"\n")])
    selected[0]["message"] += " invented"
    with pytest.raises(ValueError):
        module.verify_source_projection(selected, [original])


def test_upper_boundary_probe_is_separate_synthetic_instrumentation():
    module = harness()
    _, scope = module.select_calibration_events([event()], case_id="case-001")
    probe = module.upper_boundary_probe(scope)
    assert module.utc(probe["observed_at"]) == scope.time_to
    assert probe["event_type"] == "acceptance_probe"
    assert probe["probe_kind"] == "synthetic_end_boundary"
    assert probe["dataset_id"] == scope.dataset_id
