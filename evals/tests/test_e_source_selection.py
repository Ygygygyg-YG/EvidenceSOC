"""Synthetic terminal integrity and controlled semantic replay, with no services."""

from __future__ import annotations

import json
from hashlib import sha256

import pytest

from evals.contracts import canonical_hash
from evals.tests.test_analysis_import import artifact_source


def terminal_fixture():
    rows, records = [], []
    for index in range(36):
        row = {
            "slot_id": f"development-{index:024x}",
            "case_id": "ait-test",
            "request": {"ordinal": index},
            "input_hashes": {},
        }
        rows.append(row)
    bundle = {"rows": rows}
    bundle["bundle_sha256"] = canonical_hash(bundle)
    for row in rows:
        result = json.dumps({"execution_status": "failed", "model_ledger": []}).encode()
        records.append(
            {
                "started": {
                    "slot_id": row["slot_id"],
                    "bundle_sha256": bundle["bundle_sha256"],
                    "request_sha256": canonical_hash(row["request"]),
                    "input_hashes": {},
                },
                "attempt": {
                    "slot_id": row["slot_id"],
                    "bundle_sha256": bundle["bundle_sha256"],
                    "status": "failed",
                    "result_sha256": sha256(result).hexdigest(),
                },
                "result_raw": result,
            }
        )
    return bundle, records


def test_all_36_terminal_failures_need_no_http_or_seed_artifacts():
    from evals.e_source_selection import validate_terminal_records

    bundle, records = terminal_fixture()
    assert validate_terminal_records(bundle, records) == ["failed"] * 36


@pytest.mark.parametrize(
    "mutation",
    [
        "order",
        "duplicate",
        "result_hash",
        "nonterminal",
        "bundle_hash",
        "started_request",
    ],
)
def test_terminal_records_reject_rebound_or_incomplete_provenance(mutation):
    from evals.e_source_selection import validate_terminal_records

    bundle, records = terminal_fixture()
    if mutation == "order":
        records.reverse()
    elif mutation == "duplicate":
        bundle["rows"][1] = bundle["rows"][0]
    elif mutation == "result_hash":
        records[0]["result_raw"] += b" "
    elif mutation == "nonterminal":
        records[0]["attempt"]["status"] = "running"
    elif mutation == "bundle_hash":
        bundle["bundle_sha256"] = "f" * 64
    else:
        records[0]["started"]["request_sha256"] = "f" * 64
    with pytest.raises(ValueError):
        validate_terminal_records(bundle, records)


@pytest.mark.parametrize("verdict", ["benign", "unknown"])
def test_completed_non_attack_is_legal_only_after_full_original_replay(
    tmp_path, verdict
):
    from evals.adapters.analysis_import import _read_manifest
    from evals.e_source_selection import replay_completed_source

    anchor = artifact_source(tmp_path, verdict=verdict)
    manifest, blobs = _read_manifest(anchor)
    replay = replay_completed_source(anchor, manifest, blobs)
    assert replay["legally_validated"] is True
    assert replay["verdict"] == verdict
    assert replay["qualified"] is False


def test_non_attack_with_substituted_citation_is_not_counted_legal(tmp_path):
    from evals.adapters.analysis_import import _read_manifest
    from evals.e_source_selection import replay_completed_source

    anchor = artifact_source(tmp_path, verdict="unknown")
    manifest, blobs = _read_manifest(anchor)
    value = json.loads(blobs["result"])
    value["model_ledger"][-1]["raw_response"]["choices"][0]["message"]["content"] = (
        '{"diagnosis":{"verdict":"unknown","evidence_ids":["EV-missing"]}}'
    )
    blobs["result"] = json.dumps(value).encode()
    with pytest.raises(ValueError):
        replay_completed_source(anchor, manifest, blobs)


def test_non_equivalent_original_source_is_not_executed_or_accepted(tmp_path):
    from evals.adapters.analysis_import import _read_manifest
    from evals.e_source_selection import replay_completed_source

    anchor = artifact_source(tmp_path, verdict="unknown", original_reject=True)
    manifest, blobs = _read_manifest(anchor)
    with pytest.raises(ValueError, match="original validator"):
        replay_completed_source(anchor, manifest, blobs)
