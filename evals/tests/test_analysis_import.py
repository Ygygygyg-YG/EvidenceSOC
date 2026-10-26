"""Synthetic original artifacts only; never read or repair the running 36 slots."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from evals.adapters.model_client import project_context
from evals.adapters.remediation_contracts import CAMPAIGN, RemediationRequest
from evals.adapters.seed import load_seed
from evals.contracts import AdapterResult, canonical_hash


def artifact_source(
    root: Path, *, verdict="attack", raw=None, index=0, original_reject=False
):
    from evals.adapters.analysis_import import SourceAnchor, validation_source_hashes

    root.mkdir(parents=True, exist_ok=True)
    agent = root / "agent"
    agent.mkdir()
    event = {
        "source": "synthetic",
        "event_type": "observation",
        "severity": "info",
        "observed_at": "2026-10-22T00:00:00Z",
        "message": "Observed access",
        **({"host": "synthetic-host"} if raw is None else raw),
    }
    (agent / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
    source_root = root / "original-source"
    project_root = Path(__file__).resolve().parents[2]
    source_files = list(
        (project_root / "services/backend/src/evidencesoc").rglob("*.py")
    )
    source_files += [
        project_root / name
        for name in (
            "evals/contracts.py",
            "evals/adapters/seed.py",
            "evals/adapters/diagnosis.py",
            "evals/adapters/model_client.py",
            "evals/adapters/remediation_contracts.py",
        )
    ]
    source_hashes = {}
    for original in source_files:
        relative = original.relative_to(project_root).as_posix()
        target = source_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(original.read_bytes())
        if original_reject and relative.endswith("agents/nodes/__init__.py"):
            target.write_bytes(
                target.read_bytes()
                + b"\ndef validate_output_citations(*args, **kwargs):\n    raise ValueError('synthetic original validator refusal')\n"
            )
        source_hashes[relative] = sha256(target.read_bytes()).hexdigest()
    source_receipt = {
        "source_commit": "a" * 40,
        "archive_sha256": "b" * 64,
        "files": source_hashes,
    }
    slot = "development-" + canonical_hash(index)[:24]
    request = RemediationRequest(
        run_id=CAMPAIGN + "-" + canonical_hash([slot, 1])[:16],
        slot_id=slot,
        case_id="ait-" + "0" * 24,
        group="B3",
        purpose="development",
        source_commit="a" * 40,
        source_sha256=canonical_hash(source_receipt),
        config_sha256="c" * 64,
        agent_sha256=sha256((agent / "events.jsonl").read_bytes()).hexdigest(),
        budget_identity={
            "schema_version": "task13-original-budget-identity-v1",
            "baseline_count": 3350,
            "baseline_max_rowid": 3350,
            "baseline_sha256": "d" * 64,
        },
        rag_mode="disabled",
        initial_query="Observed access",
        initial_query_sha256=sha256(b"Observed access").hexdigest(),
    )
    seed = load_seed(
        request.worker_spec().model_copy(
            update={"run_id": CAMPAIGN + "-development-seed"}
        ),
        agent,
    )
    ev = seed["evidence"][0]["evidence_id"]
    analysis = {
        "origin": None,
        "classification": None,
        "diagnosis": {
            "verdict": verdict,
            "taxonomy_status": "out_of_taxonomy"
            if verdict == "attack"
            else "not_applicable"
            if verdict == "benign"
            else "unknown",
            "evidence_ids": [ev],
        },
    }
    from evidencesoc.agents.models import AnalysisOutput

    analysis = AnalysisOutput.model_validate(analysis).model_dump(mode="json")
    context, projection = project_context(
        {"alerts": seed["alerts"], "evidence": seed["evidence"], "knowledge": []},
        request.model,
    )
    payload = {
        "model": request.model.requested_model,
        "messages": [
            {"role": "system", "content": "synthetic recorded prompt"},
            {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
        ],
    }
    body = json.dumps(payload, ensure_ascii=False).encode()
    response = {
        "id": "synthetic-response",
        "model": request.model.requested_model,
        "choices": [
            {
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(analysis)},
            }
        ],
    }
    record = {
        "physical_request_id": "synthetic-physical",
        "role": "analyze",
        "parse_status": "valid",
        "physical_attempt": 1,
        "slot_id": slot,
        "run_id": request.run_id,
        "case_id": request.case_id,
        "request_sha256": canonical_hash(payload),
        "context_projection": projection,
        "raw_response": response,
    }
    detail = {
        "slot_id": slot,
        "run_id": request.run_id,
        "fixed_seed_sha256": canonical_hash(seed),
        "model_config_sha256": canonical_hash(request.model),
        "mode": "disabled",
        "entry_schema": "AnalysisOutput",
        "entry_schema_sha256": canonical_hash(AnalysisOutput.model_json_schema()),
        "knowledge_returned": 0,
        "knowledge_returned_ids": [],
        "knowledge_in_context": 0,
        "payloads": [
            {
                "physical_request_id": record["physical_request_id"],
                "payload_path": "model-http-01.json",
                "http_body_path": "model-http-01.body.json",
                "http_body_sha256": sha256(body).hexdigest(),
                "request_sha256": canonical_hash(payload),
                "messages_sha256": canonical_hash(payload["messages"]),
                "knowledge_ids": [],
                "context_bytes": len(payload["messages"][-1]["content"].encode()),
            }
        ],
    }

    def write(name, value):
        path = root / name
        path.write_bytes(
            value
            if isinstance(value, bytes)
            else json.dumps(value, sort_keys=True).encode()
        )
        return {
            "path": str(path.absolute()),
            "size": path.stat().st_size,
            "sha256": sha256(path.read_bytes()).hexdigest(),
        }

    knowledge_ref = write("returned-knowledge.json", [])
    condition_ref = write("development-condition.json", detail)
    result = AdapterResult(
        diagnostic_snapshot={
            **analysis,
            "sealed_after": "analyze",
            "sealed_at": "2026-10-22T00:01:00Z",
        },
        diagnosis_status="succeeded",
        product_status="analysis_only",
        evidence_registry=seed["registry"],
        model_ledger=[record],
        resources={"development": detail},
        artifact_hashes={
            "returned_knowledge": knowledge_ref["sha256"],
            "development_condition": condition_ref["sha256"],
        },
    ).model_dump(mode="json")
    request_dict = request.model_dump(mode="json")
    row = {
        "slot_id": slot,
        "case_id": request.case_id,
        "request": request_dict,
        "input_hashes": {"events.jsonl": request.agent_sha256},
    }
    bundle_rows = []
    for ordinal in range(36):
        other_slot = "development-" + canonical_hash(ordinal)[:24]
        other_request = {
            **request_dict,
            "slot_id": other_slot,
            "run_id": CAMPAIGN + "-" + canonical_hash([other_slot, 1])[:16],
        }
        bundle_rows.append({**row, "slot_id": other_slot, "request": other_request})
    bundle = {"purpose": "development", "rows": bundle_rows}
    bundle["bundle_sha256"] = canonical_hash(bundle)
    result_ref = write("result.json", result)
    manifest = {
        "schema_version": "task13-analysis-artifacts-v1",
        "order_index": index,
        "source_row_id": slot,
        "successful_physical_request_id": record["physical_request_id"],
        "validation_source_sha256": validation_source_hashes(),
        "artifacts": {
            "row": write("row.json", row),
            "request": write("request.json", request_dict),
            "bundle": write("bundle36.json", bundle),
            "started": write(
                "started.json",
                {
                    "slot_id": slot,
                    "bundle_sha256": bundle["bundle_sha256"],
                    "request_sha256": canonical_hash(request_dict),
                },
            ),
            "attempt": write(
                "attempt.json",
                {
                    "slot_id": slot,
                    "bundle_sha256": bundle["bundle_sha256"],
                    "status": "completed",
                    "result_sha256": result_ref["sha256"],
                },
            ),
            "result": result_ref,
            "stdout": write("worker.stdout.json", result),
            "seed": write("seed.json", seed),
            "registry": write("registry.json", seed["registry"]),
            "events": {
                "path": str((agent / "events.jsonl").absolute()),
                "size": (agent / "events.jsonl").stat().st_size,
                "sha256": request.agent_sha256,
            },
            "knowledge": knowledge_ref,
            "condition": condition_ref,
            "payload_1": write("model-http-01.json", payload),
            "body_1": write("model-http-01.body.json", body),
        },
    }
    manifest_ref = write("manifest.json", manifest)
    manifest["artifacts"]["source_receipt"] = write(
        "original-source/source_receipt.json", source_receipt
    )
    for relative, digest in source_hashes.items():
        path = source_root / relative
        manifest["artifacts"]["original_source:" + relative] = {
            "path": str(path.absolute()),
            "size": path.stat().st_size,
            "sha256": digest,
        }
    manifest_ref = write("manifest.json", manifest)
    return SourceAnchor(
        root=str(root.absolute()),
        manifest_path=manifest_ref["path"],
        manifest_sha256=manifest_ref["sha256"],
        source_row_id=slot,
        case_id=request.case_id,
        order_index=index,
        request_sha256=canonical_hash(request_dict),
        original_bundle_sha256=bundle["bundle_sha256"],
    )


def change(anchor, artifact, edit, *, rebind=False):
    """Rebinding deliberately tests cross-artifact checks beyond file hashes."""
    manifest_path = Path(anchor.manifest_path)
    manifest = json.loads(manifest_path.read_bytes())
    ref = manifest["artifacts"][artifact]
    path = Path(ref["path"])
    value = json.loads(path.read_bytes())
    edit(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    if rebind:
        ref.update(
            size=path.stat().st_size, sha256=sha256(path.read_bytes()).hexdigest()
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        anchor = anchor.model_copy(
            update={"manifest_sha256": sha256(manifest_path.read_bytes()).hexdigest()}
        )
    return anchor


def test_replays_original_success_and_returns_immutable_verified_payload(tmp_path):
    from evals.adapters.analysis_import import verify_analysis_source

    source = verify_analysis_source(artifact_source(tmp_path))
    delta = source.product_values()
    assert delta["diagnosis"]["verdict"] == "attack"
    assert delta["attack_steps"] == []
    assert delta["analysis_import_provenance"]["reconstruct_executed"] is False
    delta["diagnosis"]["verdict"] = "benign"
    assert source.product_values()["diagnosis"]["verdict"] == "attack"


def test_verified_provenance_binds_original_analysis_and_bounded_import_values(
    tmp_path,
):
    from evidencesoc.agents.models import AnalysisOutput

    from evals.adapters.analysis_import import verify_analysis_source

    anchor = artifact_source(tmp_path)
    source = verify_analysis_source(anchor)
    values = source.product_values()
    provenance = values.pop("analysis_import_provenance")
    request = json.loads((tmp_path / "request.json").read_bytes())
    result = json.loads((tmp_path / "result.json").read_bytes())
    original_reply = result["model_ledger"][-1]["raw_response"]["choices"][0][
        "message"
    ]["content"]
    original_output = AnalysisOutput.model_validate_json(original_reply).model_dump(
        mode="json"
    )
    assert provenance["analysis_output_sha256"] == canonical_hash(original_output)
    assert provenance["imported_values_sha256"] == canonical_hash(values)
    assert provenance["dataset"] == "ait"
    assert provenance["agent_sha256"] == request["agent_sha256"]
    assert provenance["request_sha256"] == anchor.request_sha256
    assert provenance["manifest_sha256"] == anchor.manifest_sha256


@pytest.mark.parametrize(
    "artifact,edit",
    [
        ("result", lambda v: v.update(diagnosis_status="failed")),
        ("stdout", lambda v: v.update(execution_status="failed")),
        (
            "result",
            lambda v: v["diagnostic_snapshot"]["diagnosis"].update(
                attack_types=["reconnaissance"], taxonomy_status="mapped"
            ),
        ),
        ("seed", lambda v: v["evidence"][0]["raw"].update(host="replaced")),
        (
            "registry",
            lambda v: next(iter(v.values())).update(case_id="ait-" + "1" * 24),
        ),
        ("knowledge", lambda v: v.append({"knowledge_chunk_id": "KC-fake"})),
        ("request", lambda v: v.update(agent_sha256="f" * 64)),
        ("condition", lambda v: v["payloads"][0].update(request_sha256="f" * 64)),
        ("bundle", lambda v: v["rows"].reverse()),
    ],
)
def test_rejects_substituted_artifacts_even_when_manifest_is_rebound(
    tmp_path, artifact, edit
):
    from evals.adapters.analysis_import import verify_analysis_source

    source = change(artifact_source(tmp_path), artifact, edit, rebind=True)
    with pytest.raises((ValueError, PermissionError)):
        verify_analysis_source(source)


@pytest.mark.parametrize(
    "verdict,raw",
    [("benign", None), ("unknown", None), ("attack", {"account": "alice"})],
)
def test_rejects_non_attack_and_account_only_sources(tmp_path, verdict, raw):
    from evals.adapters.analysis_import import verify_analysis_source

    with pytest.raises(ValueError):
        verify_analysis_source(artifact_source(tmp_path, verdict=verdict, raw=raw))


def test_rechecks_hashes_after_verification_and_refuses_links(tmp_path):
    from evals.adapters.analysis_import import verify_analysis_source

    anchor = artifact_source(tmp_path)
    source = verify_analysis_source(anchor)
    change(anchor, "seed", lambda v: v.update(seed_bytes=0))
    with pytest.raises(ValueError):
        source.revalidate()


def test_rejects_hardlinks_even_with_same_bytes_and_bound_root(tmp_path):
    from evals.adapters.analysis_import import verify_analysis_source

    anchor = artifact_source(tmp_path)
    (tmp_path / "seed-alias.json").hardlink_to(tmp_path / "seed.json")
    with pytest.raises(ValueError, match="regular file"):
        verify_analysis_source(anchor)


def test_rejects_original_validator_source_drift(tmp_path):
    from evals.adapters.analysis_import import verify_analysis_source

    anchor = artifact_source(tmp_path)
    validator = (
        tmp_path / "original-source/services/backend/src/evidencesoc/agents/fallback.py"
    )
    validator.write_bytes(validator.read_bytes() + b"\n# changed\n")
    with pytest.raises(ValueError, match="hash or size"):
        verify_analysis_source(anchor)


def test_rejects_non_equivalent_original_source_validator_without_executing_it(
    tmp_path,
):
    from evals.adapters.analysis_import import verify_analysis_source

    with pytest.raises(ValueError, match="original validator"):
        verify_analysis_source(artifact_source(tmp_path, original_reject=True))


def test_private_ip_external_original_reply_remains_invalid(tmp_path):
    from evidencesoc.agents.models import AnalysisOutput
    from evidencesoc.agents.nodes import validate_output_citations

    artifact_source(tmp_path, raw={"source_ip": "10.1.2.3"})
    seed = json.loads((tmp_path / "seed.json").read_bytes())
    ev = seed["evidence"][0]["evidence_id"]
    output = AnalysisOutput.model_validate(
        {
            "diagnosis": {
                "verdict": "attack",
                "taxonomy_status": "out_of_taxonomy",
                "evidence_ids": [ev],
                "origin": {
                    "observed_source_ip": "10.1.2.3",
                    "entry_host": None,
                    "entry_service": None,
                    "first_seen_at": None,
                    "source_scope": "external",
                    "confidence": 0.5,
                    "evidence_ids": [ev],
                },
            }
        }
    )
    with pytest.raises(ValueError, match="source scope"):
        validate_output_citations(output, seed)


def test_selection_uses_original_order_first_three_and_reports_shortage(tmp_path):
    from evals.adapters.analysis_import import select_first_three

    anchors = [
        artifact_source(
            tmp_path / str(i), index=i, verdict="benign" if i < 2 or i > 5 else "attack"
        )
        for i in range(36)
    ]
    receipt = select_first_three(anchors)
    assert [s.provenance["order_index"] for s in receipt.sources] == [2, 3, 4]
    assert len(receipt.rows) == 36
    assert receipt.status == "selected"
    for source, row in zip(
        receipt.sources, receipt.receipt["selected_sources"], strict=True
    ):
        provenance = source.provenance
        assert row["analysis_output_sha256"] == provenance["analysis_output_sha256"]
        assert row["imported_values_sha256"] == provenance["imported_values_sha256"]
        assert row["agent_sha256"] == provenance["agent_sha256"]
        assert row["dataset"] == provenance["dataset"]
    with pytest.raises(ValueError):
        select_first_three(list(reversed(anchors)))
    anchors[3] = change(
        anchors[3], "attempt", lambda v: v.update(status="unknown"), rebind=True
    )
    anchors[4] = change(
        anchors[4], "attempt", lambda v: v.update(status="failed"), rebind=True
    )
    assert select_first_three(anchors).status == "insufficient_qualified_sources"
