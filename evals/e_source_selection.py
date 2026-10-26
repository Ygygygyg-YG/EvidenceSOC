"""Host-only source selection from actual terminal bytes, without model or DB I/O.

The older v1 selector requires a complete model manifest before checking a
terminal failure. This reader records real zero-payload failures without
manufacturing such a manifest. Newly exported terminal indexes are metadata;
selected source lineage always comes from a typed immutable portable replay.
Copied Python is read for hashes and AST equivalence only, never executed.
"""

from __future__ import annotations

import json
from collections import Counter
from hashlib import sha256
from pathlib import Path

from evidencesoc.agents.models import AnalysisOutput

from evals.adapters.analysis_import import (
    AnalysisArtifactManifest,
    Artifact,
    SourceAnchor,
    _regular,
    _verify_artifact_blobs,
    validation_source_hashes,
)
from evals.adapters.analysis_package import verify_portable_analysis_package
from evals.adapters.remediation_contracts import CAMPAIGN, RemediationRequest
from evals.adapters.seed import load_seed
from evals.contracts import AdapterResult, canonical_hash
from evals.e_planning import SOURCE_KEYS

RULE = "first-three-qualified-original-36-v1"
INDEX_SCHEMA = "task13-analysis-terminal-artifact-index-v1"


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    return json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
    )


def _bytes(value):
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        + "\n"
    ).encode()


def validate_terminal_records(bundle, records):
    """Verify every original terminal before any model-artifact requirements."""
    rows = bundle.get("rows", [])
    if (
        len(rows) != 36
        or len(records) != 36
        or len({row.get("slot_id") for row in rows}) != 36
        or canonical_hash(
            {key: value for key, value in bundle.items() if key != "bundle_sha256"}
        )
        != bundle.get("bundle_sha256")
    ):
        raise ValueError("original 36-row bundle/order binding differs")
    statuses = []
    for row, record in zip(rows, records, strict=True):
        start, attempt = record["started"], record["attempt"]
        result = _json(record["result_raw"])
        status = attempt.get("status")
        if (
            status not in {"completed", "failed", "unknown"}
            or result.get("execution_status") != status
            or start.get("slot_id") != row["slot_id"]
            or attempt.get("slot_id") != row["slot_id"]
            or start.get("bundle_sha256") != bundle["bundle_sha256"]
            or attempt.get("bundle_sha256") != bundle["bundle_sha256"]
            or start.get("request_sha256") != canonical_hash(row["request"])
            or start.get("input_hashes") != row["input_hashes"]
            or attempt.get("result_sha256") != sha256(record["result_raw"]).hexdigest()
        ):
            raise ValueError("original terminal slot/request/result binding differs")
        statuses.append(status)
    return statuses


def replay_completed_source(anchor, manifest, blobs, *, artifact_paths=None):
    """Keep the full strict replay for legal benign/unknown before rejecting them.

    Only the existing verifier's final actionable-attack gate can establish a
    legally validated non-attack. Every other refusal propagates as a gap.
    """
    try:
        values, provenance = _verify_artifact_blobs(
            anchor, manifest, blobs, artifact_paths=artifact_paths
        )
    except ValueError as error:
        if str(error) != "source is not an actionable attack":
            raise
        result = _json(blobs["result"])
        content = result["model_ledger"][-1]["raw_response"]["choices"][0]["message"][
            "content"
        ]
        output = AnalysisOutput.model_validate_json(content).model_dump(mode="json")
        if output["diagnosis"]["verdict"] not in {"benign", "unknown"}:
            raise ValueError("non-attack replay gate returned an attack") from error
        return {
            "legally_validated": True,
            "qualified": False,
            "verdict": output["diagnosis"]["verdict"],
            "analysis_output_sha256": canonical_hash(output),
            "reason": "source is not an actionable attack",
        }
    return {
        "legally_validated": True,
        "qualified": True,
        "verdict": values["diagnosis"]["verdict"],
        "analysis_output_sha256": provenance["analysis_output_sha256"],
        "imported_values_sha256": provenance["imported_values_sha256"],
        "provenance": provenance,
        "reason": None,
    }


class CapturedBytes:
    """Read an exact single-regular-file inventory and check it again at exit."""

    def __init__(self):
        self.raw = {}

    def read(self, path):
        path = Path(path).absolute()
        _regular(path, path.parent.resolve(strict=True))
        if path not in self.raw:
            self.raw[path] = path.read_bytes()
        return self.raw[path]

    def ref(self, path, *, expected=None, expected_size=None):
        path = Path(path).absolute()
        raw = self.read(path)
        digest = sha256(raw).hexdigest()
        if (
            expected is not None
            and digest != expected
            or expected_size is not None
            and len(raw) != expected_size
        ):
            raise ValueError("captured original byte binding differs")
        return {"path": str(path), "size": len(raw), "sha256": digest}

    def unchanged(self):
        for path, raw in self.raw.items():
            _regular(path, path.parent.resolve(strict=True))
            if path.read_bytes() != raw:
                raise ValueError("captured input changed during source selection")


def _child(root, name):
    part = Path(name)
    if part.is_absolute() or ".." in part.parts:
        raise ValueError("artifact escapes its original root")
    path = (root / part).absolute()
    if not path.is_relative_to(root):
        raise ValueError("artifact escapes its original root")
    return path


def _inventory_files(captured, root):
    """Hash every available byte under a row's original artifact directories."""
    refs = {}
    if root.exists():
        for path in sorted(root.rglob("*")):
            if path.is_file():
                refs[path.relative_to(root).as_posix()] = captured.ref(path)
            elif path.is_symlink():
                raise ValueError("links in original row artifact directory")
    return refs


def export_actual_source_selection(
    *,
    capsule,
    comparison_path,
    comparison_sha256,
    original_bundle_sha256,
    portable_root,
    portable_manifest_sha256,
    destination,
):
    """Create a new receipt and 36 indexes; never mutate original artifact bytes.

    Explicit comparison/bundle/package hashes are trusted host bindings. All
    original comparison inputs are rehashed, but its saved SQLite snapshot is
    historical evidence only: this function never opens a database.
    """
    capsule, destination = Path(capsule).absolute(), Path(destination).absolute()
    if destination.exists() or ".." in destination.parts:
        raise ValueError("a new absolute output directory is required")
    captured = CapturedBytes()
    comparison_ref = captured.ref(comparison_path, expected=comparison_sha256)
    comparison = _json(captured.read(comparison_path))
    if comparison.get("schema_version") != "task13-analysis36-readonly-comparison-v1":
        raise ValueError("original actual comparison schema differs")
    comparison_inputs = comparison.get("input_bindings", [])
    if not comparison_inputs or len({ref["path"] for ref in comparison_inputs}) != len(
        comparison_inputs
    ):
        raise ValueError("original comparison input inventory is incomplete")
    for ref in comparison_inputs:
        if ref.get("status") != "read":
            raise ValueError("actual terminal comparison contains an uncaptured input")
        captured.ref(ref["path"], expected=ref["sha256"], expected_size=ref["bytes"])
    if not comparison.get("database_reconciliation", {}).get(
        "bidirectional_complete_for_captured_files"
    ):
        raise ValueError("historical actual comparison is not reconciled")
    bundle_path = capsule / "bundle36.json"
    bundle = _json(captured.read(bundle_path))
    if bundle.get("bundle_sha256") != original_bundle_sha256:
        raise ValueError("trusted original bundle binding differs")
    candidate = _json(captured.read(capsule / "candidate.json"))
    fixed_refs = candidate["fixed_input_bindings"]
    for ref in fixed_refs:
        captured.ref(ref["path"], expected=ref["sha256"], expected_size=ref["bytes"])
    source_root = capsule / "source"
    source_receipt_path = source_root / "source_receipt.json"
    source_receipt = _json(captured.read(source_receipt_path))
    if (
        canonical_hash(source_receipt) != bundle["source_sha256"]
        or source_receipt["source_commit"] != bundle["source_commit"]
    ):
        raise ValueError("original source receipt differs from master bundle")
    source_refs = {"source_receipt": captured.ref(source_receipt_path)}
    for relative, digest in source_receipt["files"].items():
        source_refs["original_source:" + relative] = captured.ref(
            _child(source_root, relative), expected=digest
        )
    records = []
    for row in bundle["rows"]:
        directory = capsule / "execution-analysis36" / row["slot_id"]
        records.append(
            {
                "started": _json(captured.read(directory / "started.json")),
                "attempt": _json(captured.read(directory / "attempt.json")),
                "result_raw": captured.read(directory / "result.json"),
            }
        )
    statuses = validate_terminal_records(bundle, records)
    comparison_rows = comparison.get("rows", [])
    if len(comparison_rows) != 36:
        raise ValueError("actual comparison does not contain all original 36 rows")
    pending, rows, selected, legal_counts = {}, [], [], Counter()
    for index, (row, record, status, comparison_row) in enumerate(
        zip(bundle["rows"], records, statuses, comparison_rows, strict=True)
    ):
        request = RemediationRequest.model_validate(row["request"])
        request_hash = canonical_hash(row["request"])
        if (
            request.slot_id != row["slot_id"]
            or request.case_id != row["case_id"]
            or request.source_sha256 != bundle["source_sha256"]
            or request.source_commit != bundle["source_commit"]
            or request.agent_sha256 != row["input_hashes"]["events.jsonl"]
            or comparison_row["order"] != index + 1
            or comparison_row["slot_id"] != row["slot_id"]
            or comparison_row["status"] != status
            or comparison_row["request_sha256"] != request_hash
        ):
            raise ValueError("original request or comparison row binding differs")
        result = AdapterResult.model_validate_json(record["result_raw"])
        event_refs = [
            ref
            for ref in fixed_refs
            if Path(ref["path"]).name == "events.jsonl"
            and ref["sha256"] == request.agent_sha256
        ]
        if len(event_refs) != 1:
            raise ValueError("original event bytes are absent or ambiguous")
        events_path = Path(event_refs[0]["path"])
        directory = capsule / "execution-analysis36" / row["slot_id"]
        refs = {
            "bundle": captured.ref(bundle_path),
            "events": captured.ref(events_path),
            **source_refs,
        }
        refs.update(
            {
                name: captured.ref(directory / (name + ".json"))
                for name in ("started", "attempt", "result")
            }
        )
        nonce = (result.isolation_evidence.get("probe") or {}).get("nonce")
        if not isinstance(nonce, str) or not nonce or Path(nonce).name != nonce:
            raise ValueError("original worker nonce is missing or unsafe")
        worker = (
            capsule
            / "worker-output"
            / request.run_id
            / request.case_id
            / request.group
            / nonce
        )
        controller = worker.with_name(nonce + ".controller")
        files = {
            "execution": _inventory_files(captured, directory),
            "worker": _inventory_files(captured, worker),
            "controller": _inventory_files(captured, controller),
        }
        refs["stdout"] = captured.ref(controller / "worker-stdout.bin")
        detail = result.resources.get("development") or {}
        ledger = result.model_ledger
        physical_refs = []
        if len(ledger) != len(comparison_row["attempts"]):
            raise ValueError("actual raw response ledger count differs from comparison")
        for ordinal, (entry, historical) in enumerate(
            zip(ledger, comparison_row["attempts"], strict=True), 1
        ):
            if any(
                entry[key] != historical.get(key)
                for key in entry
                if key != "raw_response"
            ):
                raise ValueError(
                    "actual physical ledger differs from immutable comparison"
                )
            if canonical_hash(entry.get("raw_response")) != historical["candidate"].get(
                "raw_response_sha256"
            ):
                raise ValueError(
                    "actual raw provider response differs from immutable comparison"
                )
            if historical.get("database_match", {}).get("status") != "matched":
                raise ValueError("historical physical budget reconciliation is missing")
            recorded = detail.get("payloads", [])[ordinal - 1]
            for key, name in (
                ("payload_path", "payload_"),
                ("http_body_path", "body_"),
            ):
                refs[name + str(ordinal)] = captured.ref(_child(worker, recorded[key]))
            body = captured.read(refs["body_" + str(ordinal)]["path"])
            payload = _json(captured.read(refs["payload_" + str(ordinal)]["path"]))
            if (
                _json(body) != payload
                or sha256(body).hexdigest() != recorded["http_body_sha256"]
                or canonical_hash(payload) != entry["request_sha256"]
            ):
                raise ValueError("actual physical HTTP bytes differ")
            physical_refs.append(
                {
                    "physical_request_id": entry["physical_request_id"],
                    "raw_response": {
                        "path": refs["result"]["path"],
                        "json_pointer": f"/model_ledger/{ordinal - 1}/raw_response",
                        "canonical_sha256": canonical_hash(entry.get("raw_response")),
                    },
                }
            )
        prefix = f"rows/{index:02d}"
        projections = {}
        for name, value in (("row", row), ("request", row["request"])):
            relative = prefix + "/" + name + "-projection.json"
            pending[relative] = _bytes(value)
            projections[name] = {
                "path": str(destination / relative),
                "size": len(pending[relative]),
                "sha256": sha256(pending[relative]).hexdigest(),
                "origin": "new projection from original master bundle",
            }
        replay = {
            "legally_validated": False,
            "qualified": False,
            "verdict": None,
            "reason": "original terminal attempt did not succeed",
        }
        index_value = {
            "schema_version": INDEX_SCHEMA,
            "order_index": index,
            "source_row_id": row["slot_id"],
            "source_status": status,
            "original_bundle_sha256": original_bundle_sha256,
            "artifacts": refs,
            "all_available_files": files,
            "generated_projections": projections,
            "physical_responses": physical_refs,
            "availability": {
                "http_payloads": "present"
                if ledger
                else "not_applicable_no_original_model_attempt",
                "successful_snapshot": "present"
                if result.diagnostic_snapshot is not None
                else "absent_original_terminal_failure",
                "original_analysis_manifest": "not_required_for_terminal_index; qualified_source_requires_separate_immutable_portable_lineage",
            },
        }
        index_relative = prefix + "/index.json"
        if status == "completed":
            refs["condition"] = captured.ref(worker / "development-condition.json")
            refs["knowledge"] = captured.ref(worker / "returned-knowledge.json")
            seed = load_seed(
                request.worker_spec().model_copy(
                    update={"run_id": CAMPAIGN + "-development-seed"}
                ),
                events_path.parent,
            )
            for name, value in (("seed", seed), ("registry", result.evidence_registry)):
                relative = (
                    prefix
                    + "/"
                    + (
                        "recomputed-seed.json"
                        if name == "seed"
                        else "registry-projection.json"
                    )
                )
                pending[relative] = _bytes(value)
                projections[name] = {
                    "path": str(destination / relative),
                    "size": len(pending[relative]),
                    "sha256": sha256(pending[relative]).hexdigest(),
                    "origin": "controlled recomputation from original events"
                    if name == "seed"
                    else "new projection from original terminal result",
                }
            blobs = {key: captured.read(ref["path"]) for key, ref in refs.items()}
            blobs.update(
                {
                    name: pending[
                        str(Path(ref["path"]).relative_to(destination)).replace(
                            "\\", "/"
                        )
                    ]
                    for name, ref in projections.items()
                }
            )
            descriptor = AnalysisArtifactManifest(
                schema_version="task13-analysis-artifacts-v1",
                order_index=index,
                source_row_id=row["slot_id"],
                successful_physical_request_id=ledger[-1]["physical_request_id"],
                validation_source_sha256=validation_source_hashes(),
                artifacts={
                    name: Artifact.model_validate(
                        {key: ref[key] for key in ("path", "size", "sha256")}
                    )
                    for name, ref in {**refs, **projections}.items()
                },
            )
            anchor = SourceAnchor(
                root=str(capsule),
                manifest_path=str(destination / prefix / "index.json"),
                manifest_sha256=sha256(_bytes(index_value)).hexdigest(),
                source_row_id=row["slot_id"],
                case_id=row["case_id"],
                order_index=index,
                request_sha256=request_hash,
                original_bundle_sha256=original_bundle_sha256,
            )
            replay = replay_completed_source(
                anchor,
                descriptor,
                blobs,
                artifact_paths={
                    name: Path(ref["path"])
                    for name, ref in {**refs, **projections}.items()
                },
            )
            legal_counts[replay["verdict"]] += 1
            if (
                comparison_row["validated_verdict"] != replay["verdict"]
                or comparison_row["diagnosis_validation"]
                != "passed_local_frozen_validators_and_sealed_reply_match"
            ):
                raise ValueError(
                    "controlled actual semantic replay differs from original comparison"
                )
        pending[index_relative] = _bytes(index_value)
        index_hash = sha256(pending[index_relative]).hexdigest()
        base = {
            "source_row_id": row["slot_id"],
            "order_index": index,
            "case_id": row["case_id"],
            "dataset": row["case_id"].split("-", 1)[0],
            "agent_sha256": request.agent_sha256,
            "request_sha256": request_hash,
            "manifest_sha256": index_hash,
            "manifest_semantics": INDEX_SCHEMA,
            "terminal_index_path": str(destination / index_relative),
            "terminal_index_sha256": index_hash,
            "source_status": status,
            "status": "rejected",
            "reason": replay["reason"],
            "legally_validated": replay["legally_validated"],
            "validated_verdict": replay["verdict"],
            "semantic_replay": {
                key: value for key, value in replay.items() if key != "provenance"
            },
        }
        if replay["qualified"]:
            source = verify_portable_analysis_package(
                Path(portable_root), portable_manifest_sha256
            )
            provenance = source.provenance
            expected = {
                **base,
                "analysis_output_sha256": replay["analysis_output_sha256"],
                "imported_values_sha256": replay["imported_values_sha256"],
            }
            if any(
                expected[key] != provenance[key]
                for key in SOURCE_KEYS
                if key != "manifest_sha256"
            ):
                raise ValueError(
                    "typed portable replay does not bind the actual qualified source"
                )
            base.update({key: provenance[key] for key in SOURCE_KEYS})
            base.update(
                manifest_semantics="immutable-original-analysis-manifest-v1",
                source_package_manifest_sha256=provenance[
                    "source_package_manifest_sha256"
                ],
                status="selected"
                if len(selected) < 3
                else "qualified_after_first_three",
            )
            if len(selected) < 3:
                selected.append({key: base[key] for key in SOURCE_KEYS})
        rows.append(base)
    captured.unchanged()
    receipt = {
        "schema_version": "task13-analysis-source-selection-v1",
        "rule": RULE,
        "rule_sha256": canonical_hash(RULE),
        "status": "selected"
        if len(selected) == 3
        else "insufficient_qualified_sources",
        "original_bundle_sha256": original_bundle_sha256,
        "rows": rows,
        "selected_sources": selected,
        "related_case_duplicates": [
            {
                "case_id": case,
                "source_row_ids": [
                    row["source_row_id"] for row in selected if row["case_id"] == case
                ],
            }
            for case, count in Counter(row["case_id"] for row in selected).items()
            if count > 1
        ],
        "terminal_reader": {
            "schema_version": "task13-actual-terminal-selection-reader-v1",
            "source_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "comparison": comparison_ref,
            "comparison_inputs_rehashed": len(comparison_inputs),
            "captured_files_rehashed": len(captured.raw),
            "all_captured_files_unchanged": True,
            "terminal_counts": dict(Counter(statuses)),
            "legally_validated_diagnoses": dict(legal_counts),
            "qualified_source_count": len(selected),
            "independent_qualified_case_count": len(
                {row["case_id"] for row in selected}
            ),
            "rejected_manifest_semantics": INDEX_SCHEMA,
            "original_manifest_hashes_fabricated": 0,
            "copied_python_executed": False,
            "paid_model_requests": 0,
            "network_calls": 0,
            "database_opens": 0,
            "sql_mutations": 0,
            "budget_accounts_constructed": 0,
            "registration_writes": 0,
            "epoch_writes": 0,
            "authority_granted": False,
        },
    }
    pending["source-selection-receipt.json"] = _bytes(receipt)
    pending["captured-input-index.json"] = _bytes(
        {
            "schema_version": "task13-actual-source-selection-captured-inputs-v1",
            "files": [captured.ref(path) for path in sorted(captured.raw)],
        }
    )
    destination.mkdir(parents=True, exist_ok=False)
    for relative, raw in pending.items():
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    captured.unchanged()
    return receipt
