"""Read-only replay of original development artifacts, never a state-file import.

SourceAnchor values are trusted host inputs, to be bound by a future inspected
worker/selection receipt. This module does not register epochs, dispatch workers,
grant paid authority or retain live resources.
"""

from __future__ import annotations

import ast
import inspect
import json
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Literal

from evidencesoc.agents import fallback
from evidencesoc.agents.analysis_import import ImportedAnalysis
from evidencesoc.agents.models import AnalysisOutput
from evidencesoc.agents.nodes import validate_output_citations
from pydantic import Field

from evals.adapters.diagnosis import validate_diagnosis
from evals.adapters.model_client import project_context
from evals.adapters.remediation_contracts import CAMPAIGN, RemediationRequest
from evals.adapters.seed import load_seed
from evals.contracts import SHA256, AdapterResult, Contract, canonical_hash


class SourceAnchor(Contract):
    root: str
    manifest_path: str
    manifest_sha256: str = Field(pattern=SHA256)
    source_row_id: str
    case_id: str
    order_index: int = Field(ge=0, le=35)
    request_sha256: str = Field(pattern=SHA256)
    original_bundle_sha256: str = Field(default="0" * 64, pattern=SHA256)


class Artifact(Contract):
    path: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256)


class AnalysisArtifactManifest(Contract):
    schema_version: Literal["task13-analysis-artifacts-v1"]
    order_index: int = Field(ge=0, le=35)
    source_row_id: str
    successful_physical_request_id: str
    validation_source_sha256: dict[str, str]
    artifacts: dict[str, Artifact]


def validation_source_hashes():
    """Pin the local replay implementation; drift requires a new export/receipt."""
    import inspect

    import evidencesoc.agents.diagnosis as diagnosis_module
    import evidencesoc.agents.models as models_module
    import evidencesoc.agents.nodes as nodes_module
    import evidencesoc.agents.origin_scope as scope_module

    import evals.adapters.diagnosis as registry_module
    import evals.adapters.seed as seed_module

    return {
        name: sha256(Path(inspect.getfile(module)).read_bytes()).hexdigest()
        for name, module in {
            "analysis_schema": models_module,
            "diagnosis": diagnosis_module,
            "citations": nodes_module,
            "seed": seed_module,
            "fallback": fallback,
            "origin_scope": scope_module,
            "registry_validator": registry_module,
        }.items()
    } | {
        "project_context_function": sha256(
            inspect.getsource(project_context).encode()
        ).hexdigest(),
        "artifact_verifier": sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def _regular(path: Path, root: Path):
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("artifact paths must be absolute and bound to root")
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("links/reparse points are forbidden")
    resolved = path.resolve(strict=True)
    if (
        not resolved.is_relative_to(root)
        or not resolved.is_file()
        or path.stat().st_nlink != 1
    ):
        raise ValueError("artifact escapes bound root or is not a single regular file")
    return path


def _read_original_artifacts(anchor):
    """Read immutable v1 bytes; callers must separately pin their replay code.

    The public v1 reader below remains strict. A new versioned export may use
    these bytes with a freshly pinned controlled replay, never old Python code.
    """
    root = Path(anchor.root)
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("source root must be absolute")
    # Check every ancestor before resolving the root, including Windows junctions.
    for part in (root, *root.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("source root contains a link")
    root = root.resolve(strict=True)
    path = _regular(Path(anchor.manifest_path), root)
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != anchor.manifest_sha256:
        raise ValueError("manifest hash differs")
    manifest = AnalysisArtifactManifest.model_validate_json(raw)
    if (
        manifest.source_row_id != anchor.source_row_id
        or manifest.order_index != anchor.order_index
    ):
        raise ValueError("source row/order binding differs")
    blobs = {}
    for name, artifact in manifest.artifacts.items():
        path = _regular(Path(artifact.path), root)
        data = path.read_bytes()
        if len(data) != artifact.size or sha256(data).hexdigest() != artifact.sha256:
            raise ValueError("original artifact hash or size differs: " + name)
        blobs[name] = data
    return manifest, blobs


def _read_manifest(anchor):
    manifest, blobs = _read_original_artifacts(anchor)
    if manifest.validation_source_sha256 != validation_source_hashes():
        raise ValueError("replay validator source drift")
    required = {
        "row",
        "request",
        "bundle",
        "started",
        "attempt",
        "result",
        "stdout",
        "seed",
        "registry",
        "events",
        "knowledge",
        "condition",
    }
    if not required <= blobs.keys():
        raise ValueError("original artifact provenance incomplete")
    return manifest, blobs


def _validator_syntax(raw, relative):
    """Normalize only the reviewed optional response-audit metadata extension.

    No original Python is executed. Every other statement, annotation, default,
    validator and citation rule stays in the full-module comparison.
    """
    tree = ast.parse(raw)

    def syntax(value):
        return ast.dump(value, include_attributes=False)

    if relative == "services/backend/src/evidencesoc/agents/models.py":
        expected = ast.parse(
            "no_plan_reason: str | None = Field(default=None, "
            'description="Optional unverified model statement explaining a null response_plan.")'
        ).body[0]
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == "ResponseOutput":
                fields = [
                    item
                    for item in node.body
                    if isinstance(item, ast.AnnAssign)
                    and isinstance(item.target, ast.Name)
                    and item.target.id == "no_plan_reason"
                ]
                if len(fields) > 1 or any(
                    syntax(item) != syntax(expected) for item in fields
                ):
                    raise ValueError("unrecognized response audit field semantics")
                if fields:
                    position = node.body.index(fields[0])
                    previous = node.body[position - 1] if position else None
                    if not (
                        isinstance(previous, ast.AnnAssign)
                        and isinstance(previous.target, ast.Name)
                        and previous.target.id == "response_plan"
                    ):
                        raise ValueError("response audit field position differs")
                node.body = [item for item in node.body if item not in fields]
    elif relative == "services/backend/src/evidencesoc/agents/nodes/__init__.py":
        block = ast.parse(
            'no_plan_reason = data.get("no_plan_reason")\n'
            'if reason != "model_returned_null" or not (no_plan_reason and no_plan_reason.strip()):\n'
            "    no_plan_reason = None\n"
            'data["no_plan_reason"] = no_plan_reason\n'
        ).body
        missing = ast.parse(
            'reason == "model_returned_null" and no_plan_reason is None',
            mode="eval",
        ).body
        generation = ast.parse('generation = state.get("plan_generation", 0)').body[0]
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or node.name != "NodeHandlers":
                continue
            for method in node.body:
                if (
                    not isinstance(method, ast.AsyncFunctionDef)
                    or method.name != "respond"
                ):
                    continue
                normalized, index, count = [], 0, 0
                while index < len(method.body):
                    statement = method.body[index]
                    if isinstance(statement, ast.Assign) and any(
                        isinstance(target, ast.Name) and target.id == "no_plan_reason"
                        for target in statement.targets
                    ):
                        candidate = method.body[index : index + len(block)]
                        previous = method.body[index - 1] if index else None
                        following = (
                            method.body[index + len(block)]
                            if index + len(block) < len(method.body)
                            else None
                        )
                        if (
                            len(candidate) != len(block)
                            or [syntax(item) for item in candidate]
                            != [syntax(item) for item in block]
                            or count
                            or not isinstance(previous, ast.Assign)
                            or len(previous.targets) != 1
                            or not isinstance(previous.targets[0], ast.Name)
                            or previous.targets[0].id != "reason"
                            or following is None
                            or syntax(following) != syntax(generation)
                        ):
                            raise ValueError(
                                "unrecognized response audit statement semantics"
                            )
                        count += 1
                        index += len(block)
                    else:
                        normalized.append(statement)
                        index += 1
                method.body = normalized
                early, final = set(), 0
                for returned in ast.walk(method):
                    if not isinstance(returned, ast.Return) or not isinstance(
                        returned.value, ast.Dict
                    ):
                        continue
                    expression = returned.value
                    names = [
                        key.value if isinstance(key, ast.Constant) else None
                        for key in expression.keys
                    ]
                    metadata = [
                        name
                        for name in names
                        if name in {"no_plan_reason", "no_plan_reason_missing"}
                    ]
                    if not metadata:
                        continue
                    if len(metadata) != len(set(metadata)):
                        raise ValueError("duplicate response audit metadata")
                    reasons = [
                        value
                        for name, value in zip(names, expression.values, strict=True)
                        if name == "response_reason"
                    ]
                    if len(reasons) != 1:
                        raise ValueError("response audit return position differs")
                    reason = reasons[0]
                    early_code = (
                        reason.value if isinstance(reason, ast.Constant) else None
                    )
                    is_early = early_code in {
                        "invalid_diagnosis_snapshot",
                        "no_actionable_target",
                    }
                    is_final = (
                        isinstance(reason, ast.Name)
                        and reason.id == "reason"
                        and any(
                            key is None
                            and isinstance(value, ast.Name)
                            and value.id == "data"
                            for key, value in zip(
                                expression.keys, expression.values, strict=True
                            )
                        )
                    )
                    expected_names = (
                        {"no_plan_reason", "no_plan_reason_missing"}
                        if is_early
                        else {"no_plan_reason_missing"}
                    )
                    if (not is_early and not is_final) or set(
                        metadata
                    ) != expected_names:
                        raise ValueError("response audit return metadata differs")
                    pairs = []
                    for key, value in zip(
                        expression.keys, expression.values, strict=True
                    ):
                        name = key.value if isinstance(key, ast.Constant) else None
                        if name == "no_plan_reason":
                            if (
                                not isinstance(value, ast.Constant)
                                or value.value is not None
                            ):
                                raise ValueError(
                                    "unrecognized response audit reason semantics"
                                )
                        elif name == "no_plan_reason_missing":
                            allowed = (
                                isinstance(value, ast.Constant) and value.value is False
                                if is_early
                                else syntax(value) == syntax(missing)
                            )
                            if not allowed:
                                raise ValueError(
                                    "unrecognized response audit marker semantics"
                                )
                        else:
                            pairs.append((key, value))
                    expression.keys = [key for key, _ in pairs]
                    expression.values = [value for _, value in pairs]
                    if is_early:
                        if early_code in early:
                            raise ValueError("duplicate response audit return position")
                        early.add(early_code)
                    else:
                        final += 1
                if (count or early or final) and (
                    count != 1
                    or early != {"invalid_diagnosis_snapshot", "no_actionable_target"}
                    or final != 1
                ):
                    raise ValueError("incomplete response audit metadata extension")
    return syntax(tree)


def _original_validator_equivalence(manifest, blobs, request, artifact_paths=None):
    """Compare source syntax only. Never import, evaluate or execute artifacts.

    Identical full-module ASTs establish the analysis validator semantics.
    Only exact optional response-audit metadata is normalized above; the scope
    tuple extracted to origin_scope.py still has its separate fixed-value check.
    """
    if "source_receipt" not in blobs:
        raise ValueError("original validator source export missing")
    receipt = json.loads(blobs["source_receipt"])
    if (
        receipt.get("source_commit") != request.source_commit
        or canonical_hash(receipt) != request.source_sha256
    ):
        raise ValueError("original validator source receipt differs")
    files = receipt.get("files")
    if not isinstance(files, dict):
        raise ValueError("original validator file receipt missing")  # noqa: TRY004 - invalid artifact data.
    paths = artifact_paths or {
        key: Path(ref.path) for key, ref in manifest.artifacts.items()
    }
    source_root = paths["source_receipt"].parent
    for relative, digest in files.items():
        key = "original_source:" + relative
        part = Path(relative)
        if (
            part.is_absolute()
            or ".." in part.parts
            or key not in blobs
            or sha256(blobs[key]).hexdigest() != digest
        ):
            raise ValueError("original validator source files differ")
        if paths[key] != source_root / part:
            raise ValueError("original source path binding differs")
    same_modules = (
        "evals/adapters/seed.py",
        "evals/adapters/diagnosis.py",
        "services/backend/src/evidencesoc/agents/models.py",
        "services/backend/src/evidencesoc/agents/diagnosis.py",
        "services/backend/src/evidencesoc/agents/nodes/__init__.py",
        "services/backend/src/evidencesoc/domain/models.py",
        "services/backend/src/evidencesoc/domain/response_action.py",
        "services/backend/src/evidencesoc/evidence/citations.py",
        "services/backend/src/evidencesoc/ingestion/normalize.py",
        "services/backend/src/evidencesoc/ingestion/jsonl.py",
    )
    project_root = Path(__file__).resolve().parents[2]

    for relative in same_modules:
        key = "original_source:" + relative
        if key not in blobs or _validator_syntax(
            blobs[key], relative
        ) != _validator_syntax((project_root / relative).read_bytes(), relative):
            raise ValueError(
                "original validator is not equivalent to the controlled replay: "
                + relative
            )
    model_source = blobs.get("original_source:evals/adapters/model_client.py")
    if model_source is None:
        raise ValueError("original context projection source missing")

    def definition(raw, name):
        matches = [
            node
            for node in ast.parse(raw).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ]
        if len(matches) != 1:
            raise ValueError("original validator definition missing or duplicated")
        return matches[0]

    if ast.dump(
        definition(model_source, "project_context"), include_attributes=False
    ) != ast.dump(
        ast.parse(inspect.getsource(project_context)).body[0], include_attributes=False
    ):
        raise ValueError("original context projection is not equivalent")
    old_fallback = blobs.get(
        "original_source:services/backend/src/evidencesoc/agents/fallback.py"
    )
    if old_fallback is None:
        raise ValueError("original scope/target validator missing")
    from evidencesoc.agents.origin_scope import INTERNAL_SOURCE_NETWORKS

    networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
    if INTERNAL_SOURCE_NETWORKS != networks:
        raise ValueError("controlled source scope convention changed")

    class ScopeTuple(ast.NodeTransformer):
        def visit_Assign(self, node):
            if any(
                isinstance(target, ast.Name) and target.id == "internal"
                for target in node.targets
            ):
                if ast.literal_eval(node.value) != networks:
                    raise ValueError(
                        "original validator source scope convention changed"
                    )
                return None
            return self.generic_visit(node)

        def visit_Name(self, node):
            if node.id in {"internal", "INTERNAL_SOURCE_NETWORKS"}:
                return ast.Tuple(
                    elts=[ast.Constant(n) for n in networks], ctx=ast.Load()
                )
            return node

    for name in (
        "observed_raw",
        "source_ip",
        "source_host",
        "source_scope",
        "matching_target",
        "respond",
    ):
        old = definition(old_fallback, name)
        current = ast.parse(inspect.getsource(getattr(fallback, name))).body[0]
        if name == "source_scope":
            old, current = ScopeTuple().visit(old), ScopeTuple().visit(current)
        if ast.dump(old, include_attributes=False) != ast.dump(
            current, include_attributes=False
        ):
            raise ValueError(
                "original validator scope/target definition differs: " + name
            )
    return receipt


def _verify_artifacts(anchor):
    manifest, blobs = _read_manifest(anchor)
    return _verify_artifact_blobs(anchor, manifest, blobs)


def _verify_artifact_blobs(anchor, manifest, blobs, *, artifact_paths=None):
    """Replay verified bytes using only controlled code and verified input paths.

    Portable readers pass locally resolved paths; original manifest paths remain
    provenance only and must never be opened in a relocated package.
    """
    value = lambda key: json.loads(blobs[key])
    row, request_data, start, attempt = (
        value(k) for k in ("row", "request", "started", "attempt")
    )
    bundle = value("bundle")
    payload = {key: item for key, item in bundle.items() if key != "bundle_sha256"}
    rows = bundle.get("rows", [])
    if (
        canonical_hash(payload) != bundle.get("bundle_sha256")
        or bundle.get("bundle_sha256") != anchor.original_bundle_sha256
        or len(rows) != 36
        or len({item.get("slot_id") for item in rows}) != 36
        or rows[anchor.order_index] != row
        or start.get("bundle_sha256") != anchor.original_bundle_sha256
        or attempt.get("bundle_sha256") != anchor.original_bundle_sha256
    ):
        raise ValueError("original 36-row bundle/order binding differs")
    request = RemediationRequest.model_validate(request_data)
    original_receipt = _original_validator_equivalence(
        manifest, blobs, request, artifact_paths
    )
    if (
        request.purpose != "development"
        or request.group != "B3"
        or request.case_id != anchor.case_id
        or request.slot_id != anchor.source_row_id
        or canonical_hash(request_data) != anchor.request_sha256
        or row.get("request") != request_data
        or row.get("case_id") != anchor.case_id
        or row.get("slot_id") != anchor.source_row_id
        or start.get("slot_id") != request.slot_id
        or start.get("request_sha256") != anchor.request_sha256
        or attempt.get("slot_id") != request.slot_id
        or attempt.get("status") != "completed"
        or attempt.get("result_sha256") != sha256(blobs["result"]).hexdigest()
        or row.get("input_hashes", {}).get("events.jsonl") != request.agent_sha256
        or sha256(blobs["events"]).hexdigest() != request.agent_sha256
    ):
        raise ValueError(
            "original slot/request/attempt binding differs or did not succeed"
        )
    return _replay_verified_analysis(
        anchor,
        manifest,
        blobs,
        request,
        original_receipt,
        artifact_paths=artifact_paths,
    )


def _replay_verified_analysis(
    anchor, manifest, blobs, request, original_receipt, *, artifact_paths=None
):
    """Scientific replay after the caller has verified its versioned authority.

    The original entry above still requires the original 36 rows and v2 request.
    Additional development uses its independently pinned v4 registration instead.
    """
    value = lambda key: json.loads(blobs[key])
    result = AdapterResult.model_validate_json(blobs["result"])
    original = AdapterResult.model_validate_json(blobs["stdout"])
    # Controller adds isolation receipts to stdout; it must not replace any
    # diagnostic content, ledger, registry, status, errors or resource detail.
    for key in (
        "diagnostic_snapshot",
        "diagnosis_status",
        "execution_status",
        "product_status",
        "evidence_registry",
        "model_ledger",
        "tool_ledger",
        "errors",
        "resources",
    ):
        if getattr(result, key) != getattr(original, key):
            raise ValueError("saved result differs from original worker stdout")
    if (
        result.execution_status != "completed"
        or result.diagnosis_status != "succeeded"
        or result.product_status != "analysis_only"
    ):
        raise ValueError("source was not an original successful analysis")
    if any(e.get("stage") not in {"analysis"} for e in result.errors):
        raise ValueError("source has a failed post-analysis audit")
    seed = load_seed(
        request.worker_spec().model_copy(
            update={"run_id": CAMPAIGN + "-development-seed"}
        ),
        (
            artifact_paths["events"]
            if artifact_paths is not None
            else Path(manifest.artifacts["events"].path)
        ).parent,
    )
    if (
        seed != value("seed")
        or seed["registry"] != value("registry")
        or result.evidence_registry != seed["registry"]
    ):
        raise ValueError("fixed seed or case registry differs from original events")
    if any(
        item.get("case_id") != request.case_id for item in seed["registry"].values()
    ):
        raise ValueError("registry belongs to another case")
    knowledge, detail = value("knowledge"), value("condition")
    if (
        not isinstance(knowledge, list)
        or detail != result.resources.get("development")
        or detail.get("fixed_seed_sha256") != canonical_hash(seed)
        or detail.get("model_config_sha256") != canonical_hash(request.model)
        or detail.get("entry_schema") != "AnalysisOutput"
        or detail.get("entry_schema_sha256")
        != canonical_hash(AnalysisOutput.model_json_schema())
        or detail.get("slot_id") != request.slot_id
        or detail.get("run_id") != request.run_id
        or detail.get("mode") != request.rag_mode
        or detail.get("knowledge_returned") != len(knowledge)
        or detail.get("knowledge_returned_ids")
        != [k["knowledge_chunk_id"] for k in knowledge]
        or result.artifact_hashes.get("returned_knowledge")
        != sha256(blobs["knowledge"]).hexdigest()
        or result.artifact_hashes.get("development_condition")
        != sha256(blobs["condition"]).hexdigest()
        or (request.rag_mode == "disabled" and knowledge)
    ):
        raise ValueError("original seed/knowledge/condition binding differs")
    state = {
        "alerts": seed["alerts"],
        "evidence": seed["evidence"],
        "knowledge": knowledge,
    }
    expected_context, projection = project_context(state, request.model)
    ledger, payload_refs = result.model_ledger, detail.get("payloads", [])
    if not 1 <= len(ledger) <= 3 or len(ledger) != len(payload_refs):
        raise ValueError("original physical attempt provenance incomplete")
    successes = []
    for index, (entry, recorded) in enumerate(
        zip(ledger, payload_refs, strict=True), 1
    ):
        if {"payload_" + str(index), "body_" + str(index)} - blobs.keys():
            raise ValueError("actual HTTP artifacts missing")
        payload, body = value("payload_" + str(index)), blobs["body_" + str(index)]
        context = json.loads(payload["messages"][-1]["content"])
        if (
            json.loads(body) != payload
            or context != expected_context
            or recorded.get("http_body_sha256") != sha256(body).hexdigest()
            or recorded.get("request_sha256") != canonical_hash(payload)
            or entry.get("request_sha256") != canonical_hash(payload)
            or recorded.get("messages_sha256") != canonical_hash(payload["messages"])
            or recorded.get("physical_request_id") != entry.get("physical_request_id")
            or recorded.get("knowledge_ids")
            != [k["knowledge_chunk_id"] for k in context["knowledge"]]
            or entry.get("role") != "analyze"
            or entry.get("slot_id") != request.slot_id
            or entry.get("run_id") != request.run_id
            or entry.get("case_id") != request.case_id
            or entry.get("physical_attempt") != index
            or entry.get("context_projection") != projection
        ):
            raise ValueError(
                "actual HTTP input differs from original fixed seed/knowledge/request"
            )
        if entry.get("parse_status") != "valid":
            continue
        try:
            raw = entry["raw_response"]
            choice = raw["choices"][0]
            if choice.get("finish_reason") != "stop" or not raw.get("model"):
                continue
            output = AnalysisOutput.model_validate_json(choice["message"]["content"])
            if output.diagnosis is None:
                continue
            validate_output_citations(output, context)
            validate_diagnosis(output.diagnosis, seed["registry"])
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        successes.append((entry, output, context))
    if (
        not successes
        or successes[-1][0].get("physical_request_id")
        != manifest.successful_physical_request_id
    ):
        raise ValueError("no original legally successful physical response")
    entry, output, context = successes[-1]
    if entry != ledger[-1]:
        raise ValueError("source continued after its alleged successful response")
    snapshot = result.diagnostic_snapshot
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("sealed_after") != "analyze"
        or not snapshot.get("sealed_at")
    ):
        raise ValueError("original successful analysis snapshot missing")
    saved = {
        k: v for k, v in snapshot.items() if k not in {"sealed_after", "sealed_at"}
    }
    if saved != output.model_dump(mode="json"):
        raise ValueError("success snapshot differs from actual valid response")
    if output.diagnosis.verdict != "attack":
        raise ValueError("source is not an actionable attack")
    # Existing response targeting performs literal cited-observation and canonical
    # host/IP checks. It never uses taxonomy labels/confidence as a selector.
    delta = {
        **output.model_dump(mode="json"),
        "alerts": seed["alerts"],
        "evidence": seed["evidence"],
        "knowledge": context["knowledge"],
        "attack_steps": [],
        "claims": [c.model_dump(mode="json") for c in output.diagnosis.claims],
    }
    if (
        fallback.respond(
            {**delta, "incident_id": "IN-import-target-check"}
        ).response_plan
        is None
    ):
        raise ValueError("source has no cited supported host/IP target")
    provenance = {
        "schema_version": "task13-analysis-import-provenance-v1",
        "entry": "analysis_import",
        "source_row_id": anchor.source_row_id,
        "case_id": anchor.case_id,
        "dataset": anchor.case_id.split("-", 1)[0],
        "agent_sha256": request.agent_sha256,
        "order_index": anchor.order_index,
        "source_run_id": request.run_id,
        "source_commit": request.source_commit,
        "source_sha256": request.source_sha256,
        "request_sha256": anchor.request_sha256,
        "manifest_sha256": anchor.manifest_sha256,
        # Derive both from the actual legally successful reply and replayed
        # bounded inputs, never from a caller-supplied live workflow state.
        "analysis_output_sha256": canonical_hash(output.model_dump(mode="json")),
        "imported_values_sha256": canonical_hash(delta),
        "original_analysis_at": snapshot["sealed_at"],
        "successful_physical_request_id": manifest.successful_physical_request_id,
        "replay_validation_source_sha256": manifest.validation_source_sha256,
        "original_source_receipt_sha256": request.source_sha256,
        "original_validation_source_sha256": {
            key: digest
            for key, digest in original_receipt["files"].items()
            if key
            in {
                "evals/adapters/seed.py",
                "evals/adapters/diagnosis.py",
                "evals/adapters/model_client.py",
                "services/backend/src/evidencesoc/agents/models.py",
                "services/backend/src/evidencesoc/agents/nodes/__init__.py",
                "services/backend/src/evidencesoc/agents/fallback.py",
                "services/backend/src/evidencesoc/agents/diagnosis.py",
            }
        },
        "original_validator_equivalence": "ast-with-fixed-scope-and-response-audit-v2",
        "reconstruct_executed": False,
        "artifacts": {k: v.model_dump() for k, v in manifest.artifacts.items()},
    }
    return delta, provenance


def verify_analysis_source(anchor: SourceAnchor) -> ImportedAnalysis:
    anchor = SourceAnchor.model_validate(anchor).model_copy(deep=True)
    values, provenance = _verify_artifacts(anchor)
    return ImportedAnalysis._from_verified_artifacts(
        values, provenance, lambda: _verify_artifacts(anchor)
    )


@dataclass(frozen=True)
class SourceSelection:
    status: str
    sources: tuple[ImportedAnalysis, ...]
    rows: tuple[dict, ...]
    receipt: dict

    @property
    def receipt_sha256(self):
        return canonical_hash(self.receipt)


def select_first_three(anchors: list[SourceAnchor]) -> SourceSelection:
    if (
        len(anchors) != 36
        or [a.order_index for a in anchors] != list(range(36))
        or len({a.source_row_id for a in anchors}) != 36
    ):
        raise ValueError("selection requires the original 36 distinct rows in order")
    if len({a.original_bundle_sha256 for a in anchors}) != 1:
        raise ValueError("source rows belong to different original bundles")
    selected, rows = [], []
    for anchor in anchors:
        _, blobs = _read_manifest(anchor)
        source_status = json.loads(blobs["attempt"]).get("status")
        if source_status not in {"completed", "failed", "unknown"}:
            raise ValueError(
                "all 36 original attempts require auditable terminal status"
            )
        request = RemediationRequest.model_validate_json(blobs["request"])
        base = {
            "source_row_id": anchor.source_row_id,
            "order_index": anchor.order_index,
            "case_id": anchor.case_id,
            "dataset": anchor.case_id.split("-", 1)[0],
            "agent_sha256": request.agent_sha256,
            "manifest_sha256": anchor.manifest_sha256,
            "request_sha256": anchor.request_sha256,
            "source_status": source_status,
        }
        try:
            source = verify_analysis_source(anchor)
        except (ValueError, PermissionError, OSError) as error:
            rows.append({**base, "status": "rejected", "reason": str(error)})
        else:
            chosen = len(selected) < 3
            if chosen:
                selected.append(source)
            rows.append(
                {
                    **base,
                    "analysis_output_sha256": source.provenance[
                        "analysis_output_sha256"
                    ],
                    "imported_values_sha256": source.provenance[
                        "imported_values_sha256"
                    ],
                    "status": "selected" if chosen else "qualified_after_first_three",
                    "reason": None,
                }
            )
    rule = "first-three-qualified-original-36-v1"
    status = "selected" if len(selected) == 3 else "insufficient_qualified_sources"
    selected_rows = [
        {
            key: row[key]
            for key in (
                "source_row_id",
                "order_index",
                "case_id",
                "dataset",
                "agent_sha256",
                "manifest_sha256",
                "request_sha256",
                "analysis_output_sha256",
                "imported_values_sha256",
            )
        }
        for row in rows
        if row["status"] == "selected"
    ]
    duplicates = [
        {
            "case_id": case,
            "source_row_ids": [
                r["source_row_id"] for r in selected_rows if r["case_id"] == case
            ],
        }
        for case in sorted({r["case_id"] for r in selected_rows})
        if sum(r["case_id"] == case for r in selected_rows) > 1
    ]
    receipt = {
        "schema_version": "task13-analysis-source-selection-v1",
        "rule": rule,
        "rule_sha256": canonical_hash(rule),
        "status": status,
        "original_bundle_sha256": anchors[0].original_bundle_sha256,
        "rows": rows,
        "selected_sources": selected_rows,
        "related_case_duplicates": duplicates,
    }
    return SourceSelection(status, tuple(selected), tuple(rows), receipt)
