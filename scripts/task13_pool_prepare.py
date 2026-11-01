"""Inert pool compiler and explicit, separately authorized metadata adoption.

Importing this module performs no I/O. Preparation never registers an epoch,
constructs a runtime, reads credentials, or grants dispatch authority. Historical
files are read by raw pin; writes are exclusive and confined to a new candidate.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sqlite3
import subprocess
import zipfile
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path

from evals.contracts import canonical_hash

ZERO = "0" * 64
MATERIALIZATION_SHA = "6a74379649f6922d0b4bc1feabcc735e5c042d6585bc9c8d5c643d1e5e7d7363"
OLD_RECEIPT_SHA = "035aaecf7c610dbec774288ae3e409bc3fd7fc8a8f100a70727c3e3165dbcbb4"
PREDECESSOR = "456d5e85158fc5bf7df515765ea993237f31f24db1348ba12d3923dd25b9c084"
PREDECESSOR_PATH = Path(
    r"D:\传智杯\.tmp\task13-c10-live-preload-ordinal-2-20261101\handoff\trial.json"
)
DEADLINE = "2026-11-02T23:59:59+08:00"
COUNTS = {
    "new_planning_logical_max": 6,
    "new_planning_physical_max": 18,
    "planning_logical_already_consumed": 7,
    "planning_physical_already_consumed": 21,
    "planning_logical_max": 13,
    "planning_physical_max": 39,
    "total_logical_max": 14,
    "total_physical_max": 40,
}


def require(condition, message):
    if not condition:
        raise PermissionError(message)


def encode(value):
    if isinstance(value, bytes):
        return value
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def plain(path, *, exists=True):
    path = Path(path)
    require(
        path.is_absolute() and ".." not in path.parts,
        "absolute normalized path required",
    )
    for parent in (path, *path.parents):
        if parent.exists() or parent.is_symlink():
            require(
                not parent.is_symlink()
                and not parent.is_junction()
                and not getattr(parent.lstat(), "st_file_attributes", 0) & 0x400,
                "linked/reparse path forbidden",
            )
    if exists:
        require(
            path.is_file() and path.stat().st_nlink == 1,
            "independent regular file required",
        )
    return path


def pin(path, value=None):
    raw = plain(path).read_bytes() if value is None else encode(value)
    return {"path": str(path), "sha256": sha256(raw).hexdigest()}


def raw(ref):
    require(
        isinstance(ref, dict)
        and set(ref) == {"path", "sha256"}
        and re.fullmatch("[0-9a-f]{64}", ref["sha256"]),
        "exact raw pin required",
    )
    result = plain(ref["path"]).read_bytes()
    require(sha256(result).hexdigest() == ref["sha256"], "raw input pin differs")
    return result


def read(ref):
    return json.loads(raw(ref))


def refs(value):
    if isinstance(value, dict):
        if {"path", "sha256"} <= value.keys() and value.keys() <= {
            "path",
            "sha256",
            "bytes",
            "size",
        }:
            yield {key: value[key] for key in ("path", "sha256")}
        else:
            for child in value.values():
                yield from refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from refs(child)


def snapshot(path):
    """Full schema and row multiset, SELECT only, including unknown/halt rows."""
    with sqlite3.connect(plain(path).as_uri() + "?mode=ro", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        schema = db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        tables = {}
        for kind, name, _, _ in schema:
            if kind == "table":
                rows = db.execute(
                    'SELECT * FROM "' + name.replace('"', '""') + '"'
                ).fetchall()
                tables[name] = sorted(
                    json.dumps(row, default=lambda b: {"hex": b.hex()}) for row in rows
                )
        require(db.total_changes == 0, "snapshot changed account")
        return {"schema": [list(row) for row in schema], "tables": tables}


def compile_core(old, model_id):
    result = deepcopy(old)
    require(
        set(COUNTS) <= result["combined_development_calls"].keys(),
        "native quota fields differ",
    )
    result["combined_development_calls"].update(COUNTS)
    result["model_identity"]["id"] = model_id
    return result


def development_ledger(budget):
    """Preserve SQLite's real numeric values through the native Decimal(str) rule."""
    with sqlite3.connect(plain(budget).as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute(
            "SELECT r.id,r.actual,r.settled FROM reservations r JOIN supplement_requests s ON s.reservation_id=r.id WHERE s.purpose='development' ORDER BY r.id"
        ).fetchall()
    require(
        rows
        and len({row[0] for row in rows}) == len(rows)
        and all(row[1] is not None and row[2] == 1 for row in rows),
        "settled exact development ledger required",
    )
    values = [
        {"reservation_id": row[0], "actual": str(row[1]), "settled": row[2]}
        for row in rows
    ]
    spent = sum((Decimal(row["actual"]) for row in values), Decimal(0))
    require(spent.is_finite() and spent >= 0, "invalid settled development cost")
    return {"rows": values, "spent_yuan": str(spent)}


def initial_pool_spent(pool):
    ledger = read(pool["original_account_baseline"])["development_ledger"]
    rows = ledger["rows"]
    require(
        rows
        and len({row["reservation_id"] for row in rows}) == len(rows)
        and all(row["settled"] == 1 for row in rows),
        "frozen settled development ledger required",
    )
    spent = sum((Decimal(row["actual"]) for row in rows), Decimal(0))
    require(
        spent.is_finite() and spent >= 0 and str(spent) == ledger["spent_yuan"],
        "frozen development ledger sum differs",
    )
    return str(spent)


def prepared_scope_question(packet, packet_pin):
    """Canonical pre-UI question; contains the concrete scope, never a user act."""
    require(
        packet.get("schema_version") == "task13-e-timing-pool-pending-v1",
        "concrete pool packet required",
    )
    scope = {
        "scope_packet": packet_pin,
        "source_commit": packet["source_commit"],
        "source_sha256": packet["source_sha256"],
        "source_proposal": packet["source_proposal"],
        "model_proposal": packet["model_proposal"],
        "pool_proposal_sha256": packet["pool_proposal_sha256"],
        "data_scope": packet["data_scope"],
        "endpoint": packet["endpoint"],
        "quota": packet["quota"],
        "deadline": packet["deadline"],
        "participation_policy": packet["participation_policy"],
        "qualified_original_analysis": packet["qualified_original_analysis"],
        "budget_limit_cny": 6,
        "source_epoch": 10,
        "model_epoch": 7,
        "fixed_three_children": 2,
        "individual_plan_approval_required": True,
        "formal176_authorized": False,
        "f8_authorized": False,
    }
    question = (
        "是否批准以下 SHA 固定的具体工程计时池范围及其 source10/model7 元数据登记？"
        "复用原始分析和一次 C10 完成观测；保留未用的 1 次并新增 5 次逻辑规划，"
        "未来最多 6 次逻辑/18 次物理请求。每份实际计划仍需独立用户审批，"
        "不授权新分析、续期、质量重试、正式 176 或 F8。工程截止时间及预算不延长。\n"
        + json.dumps(
            scope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )
    return {
        "schema_version": "task13-pool-prepared-scope-question-v1",
        "record_kind": "prepared_question_not_user_consent",
        "scope_packet": packet_pin,
        "question": question,
        "approved_answer": "批准上述具体范围（packet SHA256="
        + packet_pin["sha256"]
        + "）",
        "automatic_approval": False,
        "actual_user_reply": None,
    }


def derive_decision(request, chat, packet_pin, chat_pin):
    """Copy one independently pinned incoming answer; never synthesize an answer."""
    from scripts.task13_e_trial import SCOPE

    require(request["scope_packet"] == packet_pin, "question binds another packet")
    require(
        set(request)
        == {"schema_version", "scope_packet", "prepared_question", "question_item_id"}
        and request["schema_version"] == "task13-pool-question-delivery-v1",
        "exact actual question delivery record required",
    )
    prepared = prepared_scope_question(read(packet_pin), packet_pin)
    require(
        read(request["prepared_question"]) == prepared,
        "prepared question does not describe exact concrete packet",
    )
    require(
        chat.get("role") == "user"
        and chat.get("source") == "actual_current_send_user_message_question_reply",
        "actual incoming user reply required",
    )
    replies = chat.get("question_reply")
    require(
        isinstance(replies, list) and len(replies) == 1,
        "one exact actual scope reply required",
    )
    reply = replies[0]
    require(
        reply
        == {
            "questionItemId": request["question_item_id"],
            "question": prepared["question"],
            "answer": prepared["approved_answer"],
        },
        "actual reply differs from concrete question",
    )
    item = json.loads(reply["questionItemId"])
    require(
        len(item) == 3
        and item[0] == "request_user_input_async"
        and isinstance(item[1], str)
        and bool(item[1])
        and type(item[2]) is int,
        "actual question call identity required",
    )
    when = datetime.fromisoformat(chat["captured_at"])
    require(
        when.tzinfo is not None and when <= datetime.now(UTC),
        "invalid actual capture time",
    )
    return {
        "schema_version": "task13-e-user-scope-decision-v1",
        "role": "user",
        "scope": SCOPE,
        "scope_packet_sha256": packet_pin["sha256"],
        "decision": "approved",
        "decided_at": chat["captured_at"],
        "record_id": "actual-current-chat/" + chat_pin["sha256"],
        "text": reply["question"] + "\n" + reply["answer"],
        "question": reply["question"],
        "answer": reply["answer"],
        "question_item_id": reply["questionItemId"],
        "actual_chat_evidence": chat_pin,
        "plan_approval_credit": 0,
        "formal176_scope": False,
        "f8_scope": False,
    }


class Documents:
    def __init__(self, root):
        self.root = plain(root, exists=False)
        self.values = {}

    def stage(self, relative, value):
        target = self.root / relative
        require(
            not Path(relative).is_absolute()
            and ".." not in Path(relative).parts
            and target not in self.values,
            "duplicate or escaping staged target",
        )
        self.values[target] = encode(value)
        return pin(target, self.values[target])

    def publish(self):
        for target in self.values:
            plain(target, exists=False)
            require(not target.exists(), "exclusive output already exists; no replay")
        for target, payload in self.values.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())

    def validate_existing(self):
        for target, payload in self.values.items():
            plain(target, exists=False)
            if target.exists():
                require(
                    plain(target).read_bytes() == payload,
                    "existing metadata bytes diverge: " + str(target),
                )

    def publish_missing(self):
        """Explicit reconcile only: byte-identical artifacts stay untouched."""
        self.validate_existing()
        for target, payload in self.values.items():
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())


def committed_source(tree, commit, old_files):
    """Native git archive export, staged in memory; all 117 bytes must match."""
    from scripts.task13_worker_runtime import EXPORT_PATHS

    tree = plain(tree, exists=False)
    require(
        tree == Path(__file__).resolve().parents[1],
        "compiler must run from evaluated source tree",
    )
    require(re.fullmatch("[0-9a-f]{40}", commit), "full committed source required")

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=tree, check=True, capture_output=True
        ).stdout

    require(
        git("rev-parse", "HEAD").decode().strip() == commit,
        "source commit is not current HEAD",
    )
    require(
        not git("status", "--porcelain", "--untracked-files=all").strip(),
        "source tree must be clean",
    )
    archive = git("archive", "--format=zip", commit, *EXPORT_PATHS)
    files = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for item in bundle.infolist():
            if item.is_dir():
                continue
            require(
                (item.external_attr >> 16) & 0o170000 != 0o120000,
                "source archive contains link",
            )
            require(
                not Path(item.filename).is_absolute()
                and ".." not in Path(item.filename).parts,
                "source archive path escapes",
            )
            files[item.filename] = bundle.read(item)
    hashes = {name: sha256(value).hexdigest() for name, value in files.items()}
    require(
        len(hashes) == 117 and hashes == old_files, "117-file measurement bytes changed"
    )
    for name, digest in hashes.items():
        require(
            pin(tree / name)["sha256"] == digest, "working measurement bytes differ"
        )
    return files, {
        "source_commit": commit,
        "archive_sha256": sha256(archive).hexdigest(),
        "files": hashes,
    }


def build_children(
    source,
    model,
    core,
    old_planning,
    lineage,
    source_files,
    root,
    *,
    packet_pin=None,
    decision_pin=None,
    decided_at=None,
):
    """Rebuild every native derived digest rather than patching hash fields."""
    from evals.e_planning import build_e_planning_registration, planning_requests
    from evals.e_timing import build_e_timing_registration

    binding = {
        "epoch_id": source["epoch_id"],
        "epoch_manifest_sha256": canonical_hash(source) if packet_pin else ZERO,
        "source_commit": source["source_commit"],
        "source_sha256": source["source_sha256"],
        "budget_identity": source["budget_identity"],
        "model_identity_binding": {
            "model_epoch_id": model["model_epoch_id"],
            "model_identity_sha256": canonical_hash(model) if packet_pin else ZERO,
        },
    }
    result = []
    for ordinal in (1, 2):
        child_id = f"{lineage['recovery_id']}-child-{ordinal}"
        planning = build_e_planning_registration(
            old_planning["source_selection_receipt"],
            registration_id=canonical_hash(child_id)[:32],
            source_package_manifest_sha256=old_planning["source"][
                "source_package_manifest_sha256"
            ],
            epoch_binding=binding,
            budget_source_receipt_sha256=source["source_sha256"],
            core_config=core,
            synthetic=False,
            mode=old_planning["mode"],
            recovery_lineage=lineage,
        )
        requests = planning_requests(planning)
        journal = str(root / child_id / "dispatch/e-planning.sqlite")
        authority = None
        if packet_pin:
            authority = {
                "schema_version": "task13-e-planning-authority-v1",
                "campaign_id": source["campaign_id"],
                "registration_sha256": canonical_hash(planning),
                "journal_path": journal,
                "scope_packet_sha256": packet_pin["sha256"],
                "decision_record_sha256": decision_pin["sha256"],
                "decision": "approved",
                "decided_by": "user",
                "decided_at": decided_at,
                "purpose": "development",
                "synthetic": False,
                "request_sha256s": [canonical_hash(q) for q in requests],
            }
            from evals.adapters.e_planning_journal import _authority

            _authority(
                authority, planning, canonical_hash(planning), canonical_hash(authority)
            )
        dispatch = {
            "schema_version": "task13-e-planning-dispatch-registration-v1",
            "campaign_id": source["campaign_id"],
            "registration_sha256": canonical_hash(planning),
            "authority_sha256": canonical_hash(authority) if authority else ZERO,
            "journal_path": journal,
            "synthetic": False,
            "planning_slot_ids": [q.planning_slot_id for q in requests],
        }
        timing = build_e_timing_registration(
            planning,
            source_files=source_files,
            f8_plan_sha256=core["f8_plan_sha256"],
            planning_dispatch_registration_receipt=dispatch,
        )
        changes = {
            key: {
                "before": old_planning["core_config"].get(key),
                "after": core.get(key),
            }
            for key in set(core) | set(old_planning["core_config"])
            if old_planning["core_config"].get(key) != core.get(key)
        }
        result.append(
            {
                "child_id": child_id,
                "registration": timing,
                "evidence_root": str(root / child_id / "host-output/timing"),
                "disclosed_control_changes": changes,
                "authority": authority,
            }
        )
    return result, binding


def compile_pending(
    data,
    *,
    root,
    tree,
    commit,
    identity,
    source_receipt,
    worker_bytes,
    host_files,
    free_policy,
    acceptance_pin,
    baseline,
):
    """Pure construction from verified original native inputs; no authority emitted."""
    from evals.adapters.planning_recovery import validate_recovery_lineage
    from evals.e_timing import BOOTSTRAP, ORDER
    from evals.timing_pool import (
        C10_EVIDENCE_ROOT,
        C10_IMPORT_PINS,
        C10_REGISTRATION,
        C10_TRIAL,
        REGISTRATION_SCHEMA,
    )
    from evals.timing_pool_controller import pool_scope_proposal

    require(
        re.fullmatch("[0-9a-f]{32}", identity),
        "stable predeclared recovery identity required",
    )
    root, tree = Path(root), Path(tree)
    docs = Documents(root)
    old_source, old_model, old_planning = (
        data["source"],
        data["model"],
        data["planning"],
    )
    require(
        old_source["epoch_number"] == 9 and old_model["model_epoch_number"] == 6,
        "original source9/model6 required",
    )
    require(
        len(source_receipt["files"]) == 117
        and source_receipt["files"] == data["receipt"]["files"],
        "measurement117 differs",
    )
    for name, digest in source_receipt["files"].items():
        require(sha256(worker_bytes[name]).hexdigest() == digest, "worker bytes differ")
        docs.stage("source/" + name, worker_bytes[name])
    receipt_pin = docs.stage("source/source_receipt.json", source_receipt)
    source_id, model_id = "e10-pool-" + identity, "model-pool-" + identity[:24]
    core = compile_core(old_planning["core_config"], model_id)
    require(core["deadline"] == DEADLINE, "engineering deadline must remain unchanged")
    core_pin = docs.stage("core-config.json", core)
    entries = {
        str(Path(path).relative_to(tree)).replace("\\", "/"): digest
        for path, digest in host_files.items()
    }
    controller = deepcopy(data["controller"])
    controller.update(
        source_commit=commit,
        entrypoints=entries,
        entrypoints_sha256=canonical_hash(entries),
    )
    controller_pin = docs.stage("controller-code-manifest.json", controller)
    new_roots = [str(root / "pool-state")]
    for ordinal in (1, 2):
        child = root / f"pool-{identity}-child-{ordinal}"
        new_roots.extend(
            str(child / name)
            for name in (
                "host-output",
                "host-output/timing",
                "host-termination",
                "worker-output",
            )
        )
    roots = sorted(set(old_source["controller_state_roots"] + new_roots))
    source = deepcopy(old_source)
    source.update(
        epoch_id=source_id,
        epoch_number=10,
        predecessor_epoch_id=old_source["epoch_id"],
        source_commit=commit,
        source_sha256=canonical_hash(source_receipt),
        config_sha256=canonical_hash(core),
        entrypoints=entries,
        entrypoints_sha256=canonical_hash(entries),
        controller_state_roots=roots,
        authority={
            "kind": "phase_scope_consent",
            "packet_sha256": None,
            "decision_record_sha256": None,
        },
    )
    source["runtime_binding"]["controller_manifest_sha256"] = controller_pin["sha256"]
    model = deepcopy(old_model)
    model.update(
        model_epoch_id=model_id,
        model_epoch_number=7,
        predecessor_model_epoch_id=old_model["model_epoch_id"],
        epoch_id=source_id,
        source_sha256=source["source_sha256"],
        config_sha256=source["config_sha256"],
        source_manifest_sha256=None,
        adoption_decision_sha256=None,
        controller_state_roots=roots,
        expected_model=core["model_identity"],
    )
    lineage = deepcopy(data["lineage"])
    lineage.update(
        recovery_id="pool-" + identity,
        predecessor_terminal_sha256=PREDECESSOR,
        execution_core_config_sha256=canonical_hash(core),
        execution_epoch_binding={
            "epoch_id": source_id,
            "source_commit": commit,
            "source_sha256": source["source_sha256"],
            "budget_identity": source["budget_identity"],
            "model_epoch_id": model_id,
        },
    )
    validate_recovery_lineage(lineage)
    lineage_pin = docs.stage("recovery-lineage.json", lineage)
    children, binding = build_children(
        source, model, core, old_planning, lineage, host_files, root
    )
    for child in children:
        child.pop("authority")
    original = data["observation"]
    baseline_pin = docs.stage("original-account-baseline.json", baseline)
    pool = {
        "schema_version": REGISTRATION_SCHEMA,
        "target_qualified": 3,
        "future_logical_limit": 6,
        "future_physical_limit": 18,
        "measurement_constants": {
            "bootstrap": BOOTSTRAP,
            "order": [list(x) for x in ORDER],
        },
        "measurement_root": str(tree),
        "original_measurement_root": str(data["old_root"] / "source"),
        "measurement_files": source_receipt["files"],
        "original_measurement_files": data["receipt"]["files"],
        "condition_identity": {
            "core_config": old_planning["core_config"],
            "actual_conditions": original["actual_conditions"],
        },
        "identity": {
            "campaign_id": old_source["campaign_id"],
            "source_commit": commit,
            "source_sha256": canonical_hash(host_files),
            "config_sha256": canonical_hash(core),
            "plan_sha256": core["f8_plan_sha256"],
        },
        "formal_binding": {
            key: binding[key]
            for key in (
                "source_sha256",
                "epoch_id",
                "epoch_manifest_sha256",
                "model_identity_binding",
            )
        },
        "children": children,
        "attempt_order": [
            {"child_id": c["child_id"], "trial_id": t["trial_id"]}
            for c in children
            for t in c["registration"]["trials"]
        ],
        "imported_observations": [
            {
                "evidence_root": str(C10_EVIDENCE_ROOT),
                "trial_id": C10_TRIAL,
                "registration_sha256": C10_REGISTRATION,
                **C10_IMPORT_PINS,
            }
        ],
        "original_account_baseline": baseline_pin,
        "execution_journal_path": str(root / "pool-state/pool-journal.jsonl"),
        "free_admission": free_policy,
        "evidence_archives": {},
    }
    archives = {}
    for ref in data.get("archive_refs", []):
        archives[ref["path"]] = docs.stage(
            "history/" + ref["sha256"] + ".json", raw(ref)
        )
    pool["evidence_archives"] = archives
    predecessor_pin = None
    if "predecessor_ref" in data:
        predecessor_pin = docs.stage(
            "history/predecessor-trial.json", raw(data["predecessor_ref"])
        )
    proposal = pool_scope_proposal(pool)
    source_proposal_pin = docs.stage(
        "activation/source-epoch-proposal.json",
        {"registrable": False, "manifest_template": source},
    )
    model_proposal_pin = docs.stage(
        "activation/model-identity-proposal.json",
        {"registrable": False, "manifest_template": model},
    )
    packet = {
        "schema_version": "task13-e-timing-pool-pending-v1",
        "status": "pending_actual_concrete_pool_scope",
        "registrable": False,
        "actual_authority": None,
        "actual_scope_decision": None,
        "scope": data["scope"]["scope"],
        "deadline": DEADLINE,
        "source_commit": commit,
        "source_tree": str(tree),
        "source_receipt": receipt_pin,
        "source_proposal": source_proposal_pin,
        "model_proposal": model_proposal_pin,
        "source_sha256": source["source_sha256"],
        "controller_manifest": controller_pin,
        "core_config": core_pin,
        "core_config_sha256": canonical_hash(core),
        "recovery_lineage": lineage,
        "recovery_lineage_sha256": canonical_hash(lineage),
        "recovery_lineage_file": lineage_pin,
        "participation_policy": core["participation_policy"],
        "pool_proposal": proposal,
        "pool_proposal_sha256": canonical_hash(proposal),
        "actual_C10_materialization": data["materialization_pin"],
        "predecessor_terminal": predecessor_pin,
        "free_acceptance": acceptance_pin,
        "quota": {
            "carry_unspent_approved_logical": 1,
            "additional_new_logical_requested": 5,
            "new_batch_logical": 6,
            "new_batch_physical_max": 18,
            **COUNTS,
        },
        "data_scope": data["scope"]["data_scope"],
        "endpoint": data["scope"]["endpoint"],
        "qualified_original_analysis": data["scope"]["qualified_original_analysis"],
        "automatic_plan_approval": False,
        "actual_individual_plan_approval_required": True,
        "no_new_analysis": True,
        "no_renewal": True,
        "no_replay_or_quality_retry": True,
        "formal176_scope": False,
        "f8_scope": False,
        "provider_requests": 0,
        "plan_approval_credit": 0,
    }
    packet_pin = docs.stage("scope-packet.json", packet)
    question_pin = docs.stage(
        "activation/prepared-scope-question.json",
        prepared_scope_question(packet, packet_pin),
    )
    payload = {
        "schema_version": "task13-pool-preparation-v1",
        "status": "pending_no_authority_or_registration",
        "scope_packet": packet_pin,
        "prepared_question": question_pin,
        "source": source,
        "model": model,
        "core": core,
        "lineage": lineage,
        "pool": pool,
        "old_planning": old_planning,
        "old_runtime": data["runtime"],
        "old_host": data["host"],
        "source_files": host_files,
        "controller_manifest": controller_pin,
        "preservation": data["preservation"],
        "database_snapshots": data["database_snapshots"],
        "actual_authority_created": 0,
        "provider_requests": 0,
    }
    preparation_pin = docs.stage("activation/preparation-receipt.json", payload)
    return docs, preparation_pin


def assert_preserved(preparation, *, skip_budget=None):
    for ref in preparation["preservation"]:
        raw(ref)
    for path, expected in preparation["database_snapshots"].items():
        if skip_budget is not None and Path(path) == Path(skip_budget):
            continue
        require(snapshot(Path(path)) == expected, "historical account/journal changed")


def gather(spec):
    from evals.adapters.model_identities import require_registered_model_identity
    from evals.adapters.remediation_worker import _budget_snapshot
    from evals.adapters.source_epochs import require_registered_epoch
    from evals.freeze import required_freeze_files
    from evals.timing_pool import (
        C10_EVIDENCE_ROOT,
        C10_IMPORT_PINS,
        C10_TRIAL,
        read_native_observation,
    )

    materialization_pin = spec["C10_materialization"]
    require(
        materialization_pin["sha256"] == MATERIALIZATION_SHA,
        "original C10 raw anchor required",
    )
    m = read(materialization_pin)
    old_root = Path(materialization_pin["path"]).parent.parent
    require(old_root == C10_EVIDENCE_ROOT.parent.parent, "original C10 path required")
    data = {
        key: read(m[field])
        for key, field in {
            "source": "source_manifest",
            "model": "model_manifest",
            "planning": "planning_registration",
            "lineage": "recovery_lineage",
            "runtime": "runtime_options",
            "controller": "controller_code_manifest",
            "scope": "execution_scope_packet",
        }.items()
    }
    data["host"] = read(pin(old_root / "activation/host-manifest.json"))
    source, model = data["source"], data["model"]
    budget = Path(source["budget_path"])
    require_registered_epoch(
        budget,
        source["epoch_id"],
        source_sha256=source["source_sha256"],
        config_sha256=source["config_sha256"],
        budget_identity=source["budget_identity"],
        manifest_sha256=canonical_hash(source),
        latest=True,
    )
    require_registered_model_identity(
        budget,
        model["model_epoch_id"],
        epoch_id=source["epoch_id"],
        source_sha256=source["source_sha256"],
        config_sha256=source["config_sha256"],
        purpose="development",
        manifest_sha256=canonical_hash(model),
        latest=True,
    )
    journal = Path(read(m["planning_authority"])["journal_path"])
    from evals.adapters.e_planning_journal import EPlanningDispatchJournal
    from evals.e_planning import planning_requests

    native_journal = EPlanningDispatchJournal.open_existing(
        journal,
        expected_registration_sha256=canonical_hash(data["planning"]),
        expected_authority_sha256=canonical_hash(read(m["planning_authority"])),
    )
    require(
        [
            native_journal.validate_request(q)["status"]
            for q in planning_requests(data["planning"])
        ]
        == ["started", "started", "unclaimed"],
        "only original untouched third allocation can carry",
    )
    predecessor_ref = {"path": str(PREDECESSOR_PATH), "sha256": PREDECESSOR}
    raw(predecessor_ref)
    data["database_snapshots"] = {
        str(path): snapshot(path) for path in (budget, journal)
    }
    with sqlite3.connect(budget.as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute(
            "SELECT r.id,r.actual,r.settled FROM reservations r JOIN supplement_requests s ON s.reservation_id=r.id WHERE s.campaign_id=?",
            (source["campaign_id"],),
        ).fetchall()
        require(
            len(rows) == 74
            and all(r[1] is not None and r[2] == 1 for r in rows)
            and sum((Decimal(str(r[1])) for r in rows), Decimal(0))
            == Decimal(".6837285600000000039"),
            "actual settled74 account changed",
        )
    config, original_rows = _budget_snapshot(budget)
    supplement_ids = {r[0] for r in rows}
    unknown = [
        list(r)
        for r in original_rows
        if r[0] is not None
        and r[1] not in supplement_ids
        and (r[6] != 1 or r[5] is None)
    ]
    require(len(unknown) == 2, "original two unknown reservations must remain")
    baseline = {
        "config": config,
        "legacy_unknown_rows": unknown,
        "development_ledger": development_ledger(budget),
    }
    data["receipt"] = read(
        {
            "path": str(old_root / "source/source_receipt.json"),
            "sha256": OLD_RECEIPT_SHA,
        }
    )
    tree = Path(spec["source_tree"])
    files, receipt = committed_source(
        tree, spec["source_commit"], data["receipt"]["files"]
    )
    names = set(required_freeze_files(tree)) | set(source["entrypoints"])
    host_files = {
        str(tree / name): pin(tree / name)["sha256"] for name in sorted(names)
    }
    for name in ("evals/e_timing.py", "evals/e_planning.py"):
        require(
            host_files[str(tree / name)] == source["entrypoints"][name],
            "native measurement controller changed",
        )
    acceptance = read(spec["free_acceptance"])
    require(
        acceptance.get("source_commit") == spec["source_commit"]
        and acceptance.get("status") == "passed"
        and acceptance.get("critical") == acceptance.get("important") == 0,
        "committed evaluated source requires actual passing free acceptance",
    )
    require(
        acceptance.get("source_files_sha256") == canonical_hash(host_files),
        "free acceptance must cover exact full host inventory",
    )
    policy = spec["free_policy"]
    require(
        set(policy)
        == {
            "gate_root",
            "helpers",
            "reader_regression",
            "reader_lowlevel",
            "public_reference",
        },
        "complete admission policy required",
    )
    helper = pin(tree / "scripts/task13_pool_admission.py")
    require(
        policy["helpers"]
        == dict.fromkeys(("assembler", "native_probe", "services"), helper),
        "three helpers must bind same frozen admission script",
    )
    for ref in refs(policy):
        raw(ref)
    # Read the native observation once; its reader checks every original capture.
    observation = read_native_observation(C10_EVIDENCE_ROOT, C10_TRIAL)
    slot = observation["binding"]["planning_slot_id"]
    start = read(pin(old_root / "host-output/slots" / slot / "decision-started.json"))
    chat = read(start["chat_record"])
    question = read(chat["prepared_question"])
    archive_refs = [start["chat_record"], chat["prepared_question"]]
    archive_refs.extend(
        question[k] for k in ("presentation_source", "preview") if k in question
    )
    archive_refs.append(
        {
            "path": str(
                Path(
                    r"D:\传智杯\.tmp\task13-c10-live-preload-ordinal-1-20261101\handoff\trial.json"
                )
            ),
            "sha256": C10_IMPORT_PINS["reviewed_trial_sha256"],
        }
    )
    preservation = {
        ref["path"]: ref
        for ref in [
            materialization_pin,
            predecessor_ref,
            *refs(m),
            *archive_refs,
            spec["free_acceptance"],
            *refs(policy),
        ]
    }
    original_timing = read(pin(C10_EVIDENCE_ROOT / "registration.json"))
    require(
        len(original_timing["source_files"]) == 169,
        "complete original host169 required",
    )
    for path, digest in original_timing["source_files"].items():
        preservation[path] = {"path": path, "sha256": digest}
    # Every byte of original exported worker and all original host inputs stays pinned.
    for name, digest in data["receipt"]["files"].items():
        ref = {"path": str(old_root / "source" / name), "sha256": digest}
        preservation[ref["path"]] = ref
    for path in old_root.rglob("*"):
        if path.is_file() and path.suffix.lower() != ".sqlite":
            ref = pin(path)
            preservation[ref["path"]] = ref
    for ref in preservation.values():
        raw(ref)
    data.update(
        old_root=old_root,
        materialization_pin=materialization_pin,
        observation=observation,
        archive_refs=archive_refs,
        predecessor_ref=predecessor_ref,
        preservation=list(preservation.values()),
    )
    assert_preserved(data)
    return data, files, receipt, host_files, baseline


def prepare(spec):
    root = plain(spec["candidate_output"], exists=False)
    require(not root.exists(), "exclusive new pending candidate required")
    gate_root = plain(spec["free_policy"]["gate_root"], exists=False)
    require(
        gate_root.is_relative_to(root),
        "free admission output must stay inside candidate",
    )
    data, files, receipt, host_files, baseline = gather(spec)
    docs, preparation_pin = compile_pending(
        data,
        root=root,
        tree=spec["source_tree"],
        commit=spec["source_commit"],
        identity=spec["recovery_id"],
        source_receipt=receipt,
        worker_bytes=files,
        host_files=host_files,
        free_policy=spec["free_policy"],
        acceptance_pin=spec["free_acceptance"],
        baseline=baseline,
    )
    assert_preserved(data)
    docs.publish()
    assert_preserved(data)
    return {
        "preparation": preparation_pin,
        "status": "pending_no_authority_or_registration",
        "provider_requests": 0,
    }


def compile_adoption(preparation, preparation_pin, request_pin, chat_pin):
    """Deterministically materialize the single actual parent answer, in memory."""
    from types import SimpleNamespace

    from evals.adapters.model_identities import (
        _authority as validate_model_authority,
    )
    from evals.adapters.model_identities import (
        _validate_manifest as validate_model,
    )
    from evals.adapters.source_epochs import _validate_manifest as validate_source
    from evals.e_planning import planning_requests
    from evals.timing_pool import (
        C10_IMPORT_PINS,
        C10_REGISTRATION,
        C10_TRIAL,
        validate_migration_marker,
    )
    from evals.timing_pool_controller import pool_scope_proposal
    from scripts.task13_e_trial import SCOPE
    from scripts.task13_timing_pool import derive_next_three_bound

    p = deepcopy(preparation)
    root = Path(preparation_pin["path"]).parent.parent
    docs = Documents(root)
    packet_pin = p["scope_packet"]
    packet = read(packet_pin)
    require(
        read(packet["source_proposal"])
        == {"registrable": False, "manifest_template": p["source"]}
        and read(packet["model_proposal"])
        == {"registrable": False, "manifest_template": p["model"]}
        and read(packet["core_config"]) == p["core"]
        and packet["recovery_lineage"] == p["lineage"]
        and packet["controller_manifest"] == p["controller_manifest"],
        "materialization templates differ from approved concrete packet",
    )
    request, chat = read(request_pin), read(chat_pin)
    require(
        request.get("prepared_question") == p["prepared_question"],
        "delivery is not bound to frozen compiler question",
    )
    decision = derive_decision(request, chat, packet_pin, chat_pin)
    decision["authorization_request"] = request_pin
    decision_pin = docs.stage("activation/scope-decision.json", decision)
    source, model = p["source"], p["model"]
    require(
        source["authority"]
        == {
            "kind": "phase_scope_consent",
            "packet_sha256": None,
            "decision_record_sha256": None,
        }
        and model["adoption_decision_sha256"]
        is model["source_manifest_sha256"]
        is None,
        "preparation authority already filled",
    )
    source["authority"].update(
        packet_sha256=packet_pin["sha256"],
        decision_record_sha256=decision_pin["sha256"],
    )
    validate_source(source)
    source_pin = docs.stage("activation/source-epoch-manifest.json", source)
    sa = {
        "schema_version": "task13-source-epoch-authority-v1",
        **source["authority"],
        "campaign_id": source["campaign_id"],
        "epoch_id": source["epoch_id"],
        "manifest_sha256": canonical_hash(source),
        "budget_identity_sha256": canonical_hash(source["budget_identity"]),
        "decision": "approved",
    }
    sa_pin = docs.stage("activation/source-epoch-authority.json", sa)
    adoption = {
        **deepcopy(decision),
        "schema_version": "task13-user-runtime-model-adoption-decision-v1",
        "kind": "runtime_model_adoption",
        "same_actual_response_as_scope_decision": decision_pin,
        "adopted_expected_identity": model["expected_model"],
        "identity_change": False,
        "source_rebind_only": True,
        "is_additional_user_answer": False,
    }
    adoption_pin = docs.stage("activation/model-adoption-decision.json", adoption)
    model.update(
        source_manifest_sha256=canonical_hash(source),
        adoption_decision_sha256=adoption_pin["sha256"],
    )
    validate_model(model)
    model_pin = docs.stage("activation/model-identity-manifest.json", model)
    confirmation = {
        "schema_version": "task13-model-identity-materialization-confirmation-v1",
        "kind": "deterministic_record_of_actual_pool_scope_reply",
        "is_additional_user_answer": False,
        "scope_packet": packet_pin,
        "actual_chat_evidence": chat_pin,
        "authorization_request": request_pin,
        "scope_decision": decision_pin,
        "adoption_decision": adoption_pin,
        "source_manifest": source_pin,
        "model_manifest": model_pin,
        "approved_identity": model["expected_model"],
        "question_item_id": decision["question_item_id"],
        "text": decision["text"],
        "decided_at": decision["decided_at"],
        "plan_approval_credit": 0,
    }
    confirmation_pin = docs.stage(
        "activation/model-identity-confirmation.json", confirmation
    )
    ma = {
        "schema_version": "task13-model-identity-authority-v1",
        "kind": "runtime_model_adoption",
        "decision": "approved",
        "manifest_sha256": canonical_hash(model),
        "adoption_decision_sha256": adoption_pin["sha256"],
        "authority_identity": model["authority_identity"],
        "confirmation_sha256": confirmation_pin["sha256"],
    }
    validate_model_authority(model, ma, canonical_hash(ma))
    ma_pin = docs.stage("activation/model-identity-authority.json", ma)
    children, binding = build_children(
        source,
        model,
        p["core"],
        p["old_planning"],
        p["lineage"],
        p["source_files"],
        root,
        packet_pin=packet_pin,
        decision_pin=decision_pin,
        decided_at=decision["decided_at"],
    )
    authorities = {child["child_id"]: child.pop("authority") for child in children}
    pool = deepcopy(p["pool"])
    pool["children"] = children
    pool["formal_binding"] = {key: binding[key] for key in pool["formal_binding"]}
    require(
        pool_scope_proposal(pool) == packet["pool_proposal"]
        and canonical_hash(packet["pool_proposal"]) == packet["pool_proposal_sha256"],
        "actual pool is not inverse of approved proposal",
    )
    pool_pin = docs.stage("activation/pool-registration.json", pool)
    hosts, materialized_children, bounds = {}, [], []
    for child in children:
        cid = child["child_id"]
        authority, timing = authorities[cid], child["registration"]
        planning = timing["planning_registration"]
        runtime = deepcopy(p["old_runtime"])
        runtime.update(
            source_commit=source["source_commit"],
            source_dir=str(root / "source"),
            output_dir=str(root / cid / "worker-output"),
            import_dispatch_path=authority["journal_path"],
            planning_authority_sha256=canonical_hash(authority),
            controller_manifest_path=p["controller_manifest"]["path"],
            model_identity_binding=binding["model_identity_binding"],
        )
        base = cid + "/activation/"
        inputs = {
            "planning_registration": docs.stage(
                base + "planning-registration.json", planning
            ),
            "timing_registration": docs.stage(
                base + "timing-registration.json", timing
            ),
            "planning_authority": docs.stage(
                base + "planning-authority.json", authority
            ),
            "runtime_options": docs.stage(base + "runtime-options.json", runtime),
            "scope_packet": packet_pin,
            "scope_decision": decision_pin,
            "pool_authority": pool_pin,
        }
        locations = {
            "agent_dir": p["old_host"]["agent_dir"],
            "output_dir": str(root / cid / "host-output"),
            "host_termination_dir": str(root / cid / "host-termination"),
        }
        readiness = {
            "schema_version": "task13-e-host-readiness-v1",
            "status": "verified",
            "scope": SCOPE,
            "synthetic": False,
            "bindings": {key: value["sha256"] for key, value in inputs.items()},
            **locations,
        }
        inputs["readiness"] = docs.stage(base + "readiness.json", readiness)
        host = {
            "schema_version": "task13-e-host-controller-v1",
            "synthetic": False,
            "inputs": inputs,
            **locations,
        }
        hosts[cid] = docs.stage(base + "host-manifest.json", host)
        docs.stage(cid + "/host-output/host-binding.json", host)
        requests = planning_requests(planning)
        for q in requests:
            docs.stage(base + f"request-{q.ordinal}.json", q.model_dump(mode="json"))
        bounds.append(
            derive_next_three_bound(SimpleNamespace(_timing=timing, _requests=requests))
        )
        materialized_children.append(
            {
                "planning": planning,
                "authority": authority,
                "dispatch": timing["planning_dispatch_registration_receipt"],
            }
        )
    from evals.timing_pool import C10_EVIDENCE_ROOT

    original = read(pin(C10_EVIDENCE_ROOT / "registration.json"))
    marker = {
        "schema_version": "task13-e-timing-pool-migration-v1",
        "pool_registration_sha256": canonical_hash(pool),
        "source_registration_sha256": C10_REGISTRATION,
        "source_journal_head_sha256": C10_IMPORT_PINS["journal_head_sha256"],
        "imported_trial_id": C10_TRIAL,
        "excluded_trial_ids": [t["trial_id"] for t in original["trials"][1:]],
        "future_trial_ids": [a["trial_id"] for a in pool["attempt_order"]],
        "parent_scope_packet_sha256": packet_pin["sha256"],
        "parent_scope_decision_sha256": decision_pin["sha256"],
    }
    validate_migration_marker(marker, pool, packet_pin, decision_pin)
    marker_pin = docs.stage("activation/migration-marker.json", marker)
    bound = max(bounds)
    payload_upper = int((bound / 3 * 1000000 - Decimal(4096) * 8) / 2 - 4096)
    capacity = {
        "schema_version": "task13-pool-next-three-capacity-v1",
        "pool_registration_sha256": canonical_hash(pool),
        "physical_requests": 3,
        "max_tokens": 4096,
        "peak_input_cny_per_million": 2,
        "peak_output_cny_per_million": 8,
        "payload_bytes_upper_bound": payload_upper,
        "next_three_upper_cny": str(bound),
        "supporting_refs": [p["controller_manifest"]],
        "bound_basis": "Pinned native request payload construction and fixed context/token upper bounds",
    }
    capacity_pin = docs.stage("activation/capacity-proof.json", capacity)
    manifest = {
        "schema_version": "task13-e-timing-pool-host-v1",
        "pool_registration": pool_pin,
        "hosts": hosts,
        "journal_path": pool["execution_journal_path"],
        "original_account_baseline": pool["original_account_baseline"],
        "migration_marker": marker_pin,
        "capacity_proof": capacity_pin,
    }
    manifest_pin = docs.stage("activation/pool-host-manifest.json", manifest)
    materialization = {
        "schema_version": "task13-pool-materialization-v1",
        "preparation": preparation_pin,
        "scope_packet": packet_pin,
        "scope_decision": decision_pin,
        "actual_scope_chat": chat_pin,
        "source": source,
        "model": model,
        "source_authority": sa,
        "model_authority": ma,
        "source_manifest": source_pin,
        "model_manifest": model_pin,
        "source_authority_file": sa_pin,
        "model_authority_file": ma_pin,
        "children": materialized_children,
        "pool": pool,
        "pool_host_manifest": manifest_pin,
        "provider_requests": 0,
        "plan_approval_credit": 0,
        "is_additional_user_answer": False,
    }
    materialization_pin = docs.stage("activation/materialization.json", materialization)
    return docs, materialization, materialization_pin


def require_exact_epoch_appends(before, after):
    """No reservation, halt, evidence or historical registration may change."""
    require(
        before["schema"] == after["schema"]
        and before["tables"].keys() == after["tables"].keys(),
        "original SQL schema changed",
    )
    for table, rows in before["tables"].items():
        current = after["tables"][table]
        if table in {"supplement_source_epochs", "supplement_model_epochs"}:
            from collections import Counter

            removed = Counter(rows) - Counter(current)
            added = Counter(current) - Counter(rows)
            require(
                not removed and sum(added.values()) == 1,
                "exactly one native epoch append required",
            )
        else:
            require(current == rows, "unrelated original SQL rows changed: " + table)


def validate_epoch_prefix(before, after, materialization):
    """Accept only the native durable prefixes (0,0), (1,0), (1,1)."""
    from collections import Counter

    require(
        before["schema"] == after["schema"]
        and before["tables"].keys() == after["tables"].keys(),
        "original SQL schema changed",
    )
    added = {}
    for table, old in before["tables"].items():
        current = after["tables"][table]
        require(
            not Counter(old) - Counter(current), "historical SQL row changed or removed"
        )
        extra = list((Counter(current) - Counter(old)).elements())
        if table in {"supplement_source_epochs", "supplement_model_epochs"}:
            require(len(extra) <= 1, "more than one epoch append")
            added[table] = [json.loads(row) for row in extra]
        else:
            require(not extra, "unrelated original SQL rows changed: " + table)
    source_rows, model_rows = (
        added["supplement_source_epochs"],
        added["supplement_model_epochs"],
    )
    require(not model_rows or source_rows, "model append without source predecessor")
    for rows, kind in ((source_rows, "source"), (model_rows, "model")):
        if not rows:
            continue
        row, manifest, authority = (
            rows[0],
            materialization[kind],
            materialization[kind + "_authority"],
        )
        if kind == "source":
            require(
                len(row) == 9
                and row[:4]
                == [
                    manifest["epoch_id"],
                    manifest["campaign_id"],
                    manifest["epoch_number"],
                    manifest["predecessor_epoch_id"],
                ]
                and json.loads(row[4]) == manifest
                and row[5] == canonical_hash(manifest)
                and row[6] == canonical_hash(authority),
                "source append has different exact authority",
            )
        else:
            require(
                len(row) == 10
                and row[:4]
                == [
                    manifest["model_epoch_id"],
                    manifest["campaign_id"],
                    manifest["model_epoch_number"],
                    manifest["predecessor_model_epoch_id"],
                ]
                and json.loads(row[4]) == manifest
                and row[5] == canonical_hash(manifest)
                and json.loads(row[6]) == authority
                and row[7] == canonical_hash(authority),
                "model append has different exact authority",
            )
    return bool(source_rows), bool(model_rows)


def require_native_prefix(budget, materialization, prefix):
    from evals.adapters.model_identities import require_registered_model_identity
    from evals.adapters.source_epochs import require_registered_epoch

    source, model = materialization["source"], materialization["model"]
    if prefix[0]:
        require_registered_epoch(
            budget,
            source["epoch_id"],
            source_sha256=source["source_sha256"],
            config_sha256=source["config_sha256"],
            budget_identity=source["budget_identity"],
            manifest_sha256=canonical_hash(source),
            latest=True,
        )
    if prefix[1]:
        require_registered_model_identity(
            budget,
            model["model_epoch_id"],
            epoch_id=source["epoch_id"],
            source_sha256=source["source_sha256"],
            config_sha256=source["config_sha256"],
            purpose="development",
            manifest_sha256=canonical_hash(model),
            latest=True,
        )


def require_unclaimed_child(child):
    from evals.adapters.e_planning_journal import EPlanningDispatchJournal
    from evals.e_planning import planning_requests

    planning, authority = child["planning"], child["authority"]
    journal = Path(authority["journal_path"])
    if not journal.exists():
        return False
    native = EPlanningDispatchJournal.open_existing(
        journal,
        expected_registration_sha256=canonical_hash(planning),
        expected_authority_sha256=canonical_hash(authority),
    )
    require(
        all(
            native.validate_request(q)["status"] == "unclaimed"
            for q in planning_requests(planning)
        ),
        "new native slot claimed; metadata reconciliation forbidden",
    )
    return True


def require_pool_genesis(pool):
    from evals.timing_pool_controller import PoolJournal

    path = Path(pool["execution_journal_path"])
    if not path.exists():
        return False
    events = PoolJournal(path, pool_sha256=canonical_hash(pool))._events()
    expected = {
        "attempts": [a["trial_id"] for a in pool["attempt_order"]],
        "imported_trial_id": pool["imported_observations"][0]["trial_id"],
        "initial_spent_yuan": initial_pool_spent(pool),
        "imported_max_seconds": 384.562,
    }
    require(
        len(events) == 1
        and events[0]["kind"] == "prepare"
        and events[0]["payload"] == expected,
        "pool has execution events or divergent genesis; cannot reconcile metadata",
    )
    return True


def adoption_marker(spec, materialization_pin):
    return {
        "schema_version": "task13-pool-adoption-start-v2",
        **{
            key: spec[key]
            for key in (
                "preparation",
                "authorization_request",
                "actual_scope_chat",
                "actual_scope_review",
            )
        },
        "materialization": materialization_pin,
        "automatic_retry": False,
        "provider_requests": 0,
    }


def require_timing_genesis(child):
    """Only native campaign registration metadata may exist before reconciliation."""
    from evals.e_timing import read_timing_journal
    from evals.verification_v2 import _json_bytes

    root, registration = Path(child["evidence_root"]), child["registration"]
    registration_path = root / "registration.json"
    events = list((root / "events").glob("*.json"))
    if not registration_path.exists():
        require(not events, "timing events without original registration")
        return False
    require(
        plain(registration_path).read_bytes() == _json_bytes(registration),
        "native timing registration bytes diverge",
    )
    if not events:
        return False  # Atomic native registration committed before its genesis.
    expected = {
        "sequence": 0,
        "previous_sha256": None,
        "registration_sha256": canonical_hash(registration),
        "synthetic": False,
        "payload": {
            "kind": "campaign.registered",
            "registration_sha256": canonical_hash(registration),
        },
    }
    require(
        len(events) == 1
        and events[0].name == "00000000-" + canonical_hash(expected) + ".json"
        and plain(events[0]).read_bytes() == _json_bytes(expected),
        "native timing execution or divergent genesis exists",
    )
    state = read_timing_journal(root)
    require(
        all(
            row["status"] == "not_started" and not row.get("review_pending")
            for row in [*state["cases"].values(), *state["records"].values()]
        ),
        "native timing execution already started",
    )
    return True


def adoption_result(materialization, materialization_pin):
    return {
        "schema_version": "task13-pool-adoption-result-v1",
        "status": "native_metadata_registered",
        "materialization": materialization_pin,
        "pool_host_manifest": materialization["pool_host_manifest"],
        "source_rows_appended": 1,
        "model_rows_appended": 1,
        "new_unclaimed_logical_slots": 6,
        "provider_requests": 0,
        "plan_approval_credit": 0,
        "fresh_free_admission_required": True,
        "original_rows_preserved": True,
    }


def require_no_active_metadata_locks(roots):
    names = {
        ".writer-lock",
        ".analysis36-campaign-lock",
        "host-writer.lock",
        ".pool-adoption-fence",
        ".rolling-adoption-lock",
        "pool-journal.jsonl.lock",
    }
    for root in roots:
        if root.exists():
            require(
                not any(path.name in names for path in root.rglob("*")),
                "active or ownerless native lock requires independent reconciliation; never remove it",
            )


@contextmanager
def offline_metadata():
    """Audit only this metadata operation, including exception unwinding."""
    import sys

    active = [True]

    def guard(event, args):
        if not active[0]:
            return
        if event.startswith("socket.") or event in {
            "subprocess.Popen",
            "os.system",
            "os.exec",
            "os.spawn",
            "os.posix_spawn",
        }:
            raise PermissionError("metadata adoption has no provider/process authority")
        if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
            require(
                Path(os.fsdecode(args[0])).name.casefold() != ".env",
                "metadata adoption cannot read credentials",
            )

    sys.addaudithook(guard)
    try:
        yield
    finally:
        active[0] = False


def adopt(spec, *, resume=False):
    """Append native metadata only; never run a plan, trial, probe or provider."""
    from evals.timing_pool import validate_pool_registration

    p = read(spec["preparation"])
    root = Path(spec["preparation"]["path"]).parent.parent
    require(
        p["status"] == "pending_no_authority_or_registration"
        and p["actual_authority_created"] == 0,
        "inert original preparation required",
    )
    require(
        datetime.now(UTC) < datetime.fromisoformat(DEADLINE),
        "engineering deadline elapsed",
    )
    budget = Path(p["source"]["budget_path"])
    assert_preserved(p, skip_budget=budget if resume else None)
    for name, digest in p["source_files"].items():
        require(pin(name)["sha256"] == digest, "frozen evaluated source changed")
    # Recheck the actual clean commit and entire worker export before adoption.
    packet = read(p["scope_packet"])
    receipt = read(packet["source_receipt"])
    scope_review = read(spec["actual_scope_review"])
    require(
        scope_review.get("schema_version") == "task13-pool-actual-scope-review-v1"
        and scope_review.get("status") == "passed"
        and scope_review.get("critical") == scope_review.get("important") == 0
        and scope_review.get("scope_packet") == p["scope_packet"]
        and scope_review.get("authorization_request") == spec["authorization_request"]
        and scope_review.get("actual_scope_chat") == spec["actual_scope_chat"],
        "independent actual scope review must bind exact incoming reply and concrete packet",
    )
    committed_source(
        Path(packet["source_tree"]), packet["source_commit"], receipt["files"]
    )
    docs, m, materialization_pin = compile_adoption(
        p, spec["preparation"], spec["authorization_request"], spec["actual_scope_chat"]
    )
    validate_pool_registration(m["pool"])
    start = root / "activation/adoption-started.json"
    expected_start = adoption_marker(spec, materialization_pin)
    if resume:
        require(
            start.exists() and read(pin(start)) == expected_start,
            "resume requires exact original authority/start marker",
        )
        docs.validate_existing()
        result_path = root / "activation/adoption-result.json"
        if result_path.exists():
            require(
                plain(result_path).read_bytes()
                == encode(adoption_result(m, materialization_pin)),
                "existing result bytes diverge",
            )
    else:
        require(
            not start.exists(),
            "adoption already started; use explicit resume-adoption with identical authority",
        )
        require(
            not any(target.exists() for target in docs.values),
            "unexpected partial adoption metadata",
        )
    original_budget = p["database_snapshots"][str(budget)]
    prefix = validate_epoch_prefix(original_budget, snapshot(budget), m)
    require_native_prefix(budget, m, prefix)
    require(resume or prefix == (False, False), "new adoption already has epoch append")
    require(
        read(m["pool"]["original_account_baseline"])["development_ledger"]
        == development_ledger(budget),
        "frozen initial ledger differs from actual original account",
    )
    for child in m["children"]:
        present = require_unclaimed_child(child)
        require(
            not present or prefix == (True, True),
            "child journal precedes native source/model registration",
        )
    pool_present = require_pool_genesis(m["pool"])
    require(
        not pool_present or all(require_unclaimed_child(c) for c in m["children"]),
        "pool genesis precedes child registrations",
    )
    for child in m["pool"]["children"]:
        require_timing_genesis(child)

    with offline_metadata():
        return complete_adoption(
            spec,
            p,
            root,
            budget,
            m,
            docs,
            materialization_pin,
            expected_start,
            original_budget,
            pool_present,
            resume=resume,
        )


def complete_adoption(
    spec,
    p,
    root,
    budget,
    m,
    docs,
    materialization_pin,
    expected_start,
    original_budget,
    pool_present,
    *,
    resume,
):
    from evals.adapters.e_planning_journal import (
        EPlanningDispatchJournal,
        register_planning_slots,
    )
    from evals.adapters.model_identities import register_model_identity
    from evals.adapters.source_epochs import register_source_epoch
    from evals.e_planning import planning_requests
    from evals.task13_rolling import rolling_quiescence
    from evals.timing_pool_controller import PoolJournal, pool_quiescence
    from scripts.task13_e_trial import ETrialController

    roots = [Path(path) for path in m["source"]["controller_state_roots"]]
    require_no_active_metadata_locks(roots)
    for path in roots:
        plain(path, exists=False)
        if not path.exists():
            require(
                path.is_relative_to(root),
                "missing historical root cannot be reconstructed",
            )
            path.mkdir(parents=True)
    # Existing rolling/pool journals are discovered by the companions. This first
    # migration has none; unexpected journals block instead of being omitted.
    for path in roots:
        require(
            all(
                found == Path(m["pool"]["execution_journal_path"]) and pool_present
                for found in path.rglob("pool-journal.jsonl")
            )
            and not list(path.rglob("rolling-events")),
            "unexpected prior pool/rolling journal requires its original controller audit",
        )
    marker = Documents(root)
    marker.stage(
        "activation/adoption-started.json",
        expected_start,
    )
    marker.publish_missing() if resume else marker.publish()
    # Keep both companions around the unchanged native source/model root locks.
    with ExitStack() as stack:
        existing_pools = (
            [
                PoolJournal(
                    m["pool"]["execution_journal_path"],
                    pool_sha256=canonical_hash(m["pool"]),
                )
            ]
            if pool_present
            else []
        )
        stack.enter_context(pool_quiescence(existing_pools, roots))
        stack.enter_context(rolling_quiescence([], roots))
        assert_preserved(p, skip_budget=budget)
        prefix = validate_epoch_prefix(original_budget, snapshot(budget), m)
        require_native_prefix(budget, m, prefix)
        source, model, sa, ma = (
            m["source"],
            m["model"],
            m["source_authority"],
            m["model_authority"],
        )
        if not prefix[0]:
            register_source_epoch(
                budget,
                source,
                expected_manifest_sha256=canonical_hash(source),
                budget_identity=source["budget_identity"],
                authority=sa,
                expected_authority_sha256=canonical_hash(sa),
            )
        if not prefix[1]:
            register_model_identity(
                budget,
                model,
                expected_manifest_sha256=canonical_hash(model),
                budget_identity=source["budget_identity"],
                authority=ma,
                expected_authority_sha256=canonical_hash(ma),
            )
    require_exact_epoch_appends(original_budget, snapshot(budget))
    registered_budget = snapshot(budget)
    for child in m["children"]:
        planning, authority = child["planning"], child["authority"]
        journal = Path(authority["journal_path"])
        require(
            journal.is_relative_to(root),
            "child journal must remain within original candidate",
        )
        journal.parent.mkdir(parents=True, exist_ok=True)
        if not require_unclaimed_child(child):
            result = register_planning_slots(
                journal,
                planning,
                expected_registration_sha256=canonical_hash(planning),
                authority=authority,
                expected_authority_sha256=canonical_hash(authority),
            )
            require(
                result == child["dispatch"],
                "native dispatch differs from deterministic preparation",
            )
        native = EPlanningDispatchJournal.open_existing(
            journal,
            expected_registration_sha256=canonical_hash(planning),
            expected_authority_sha256=canonical_hash(authority),
        )
        require(
            all(
                native.validate_request(q)["status"] == "unclaimed"
                for q in planning_requests(planning)
            ),
            "new native slot claimed",
        )
    docs.publish_missing() if resume else docs.publish()
    pool = m["pool"]
    # Host construction and native journal initialization are metadata only.
    host_manifest = read(m["pool_host_manifest"])
    for host_pin in host_manifest["hosts"].values():
        host = ETrialController(host_pin["path"], host_pin["sha256"])
        host._scope()
        with host._lock():
            host._campaign()
    if not require_pool_genesis(pool):
        PoolJournal.prepare(
            pool["execution_journal_path"],
            pool_sha256=canonical_hash(pool),
            attempts=[a["trial_id"] for a in pool["attempt_order"]],
            imported_trial_id=pool["imported_observations"][0]["trial_id"],
            now=datetime.now(UTC),
            initial_spent_yuan=initial_pool_spent(pool),
            imported_max_seconds=384.562,
        )
    require(
        snapshot(budget) == registered_budget, "metadata initialization changed budget"
    )
    for ref in p["preservation"]:
        raw(ref)
    for path, expected in p["database_snapshots"].items():
        if Path(path) != budget:
            require(snapshot(Path(path)) == expected, "historical journal changed")
    result = adoption_result(m, materialization_pin)
    result_docs = Documents(root)
    result_pin = result_docs.stage("activation/adoption-result.json", result)
    result_docs.publish_missing() if resume else result_docs.publish()
    return {"result": result_pin, **result}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "adopt", "resume-adoption"))
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--input-sha256", required=True)
    args = parser.parse_args(argv)
    spec = read({"path": str(args.input), "sha256": args.input_sha256})
    result = (
        prepare(spec)
        if args.operation == "prepare"
        else adopt(spec, resume=args.operation == "resume-adoption")
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
