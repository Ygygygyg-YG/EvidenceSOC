"""Prepare and explicitly adopt an audited five-attempt recovery; never run a plan."""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import zipfile
from copy import deepcopy
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path

from evals.contracts import canonical_hash
from scripts.task13_pool_prepare import (
    DEADLINE,
    ZERO,
    Documents,
    build_children,
    development_ledger,
    encode,
    pin,
    plain,
    raw,
    read,
    require,
    snapshot,
)

ORIGINAL_COUNTS = {
    "analysis_logical_already_consumed": 1,
    "analysis_logical_max": 1,
    "analysis_physical_already_consumed": 1,
    "analysis_physical_max": 1,
    "new_analysis_logical_max": 0,
    "new_analysis_physical_max": 0,
    "new_planning_logical_max": 6,
    "new_planning_physical_max": 18,
    "planning_logical_already_consumed": 7,
    "planning_logical_max": 13,
    "planning_physical_already_consumed": 21,
    "planning_physical_max": 39,
    "total_logical_max": 14,
    "total_physical_max": 40,
}
RECOVERY_COUNTS = {
    **ORIGINAL_COUNTS,
    "new_planning_logical_max": 5,
    "new_planning_physical_max": 15,
    "planning_logical_already_consumed": 8,
    "planning_physical_already_consumed": 24,
}
PREDECESSOR_HEAD = "68a42b853ae3ba98b9fc0605e0cf7e635f63ece6212d78d9883cda31fad7f4d9"
ORIGINAL_WORKER_RECEIPT = (
    "035aaecf7c610dbec774288ae3e409bc3fd7fc8a8f100a70727c3e3165dbcbb4"
)
AUTHORIZATION_WORKER_FILES = frozenset(
    {
        "evals/adapters/e_planning_journal.py",
        "evals/adapters/source_epochs.py",
        "evals/adapters/model_identities.py",
        "evals/adapters/additional_analysis.py",
        "evals/adapters/planning_recovery.py",
    }
)


STARTUP_COUNTS = {
    **RECOVERY_COUNTS,
    "new_planning_logical_max": 4,
    "new_planning_physical_max": 12,
    "planning_logical_already_consumed": 9,
    "planning_physical_already_consumed": 27,
}


def _profile(profile):
    require(
        profile in {"manual-v2", "startup-v3"},
        "explicit closed recovery profile required",
    )
    return profile == "startup-v3"


def _schema(kind, startup=False):
    return (
        "task13-manual-" + ("startup-" if startup else "") + "recovery-" + kind + "-v1"
    )


def _startup_schema(value, kind):
    require(
        value in {_schema(kind), _schema(kind, True)},
        "explicit recovery schema required",
    )
    return value == _schema(kind, True)


def recovery_core(original, model_id, *, profile="manual-v2"):
    startup = _profile(profile)
    require(
        canonical_hash(original["combined_development_calls"])
        == canonical_hash(RECOVERY_COUNTS if startup else ORIGINAL_COUNTS),
        "exact predecessor quota required; no extra attempts or analysis",
    )
    require(original["deadline"] == DEADLINE, "engineering deadline cannot change")
    require(
        isinstance(model_id, str) and bool(model_id.strip()), "model epoch ID required"
    )
    core = deepcopy(original)
    core["combined_development_calls"] = deepcopy(
        STARTUP_COUNTS if startup else RECOVERY_COUNTS
    )
    core["model_identity"]["id"] = model_id
    return core


def prepared_scope_question(packet, packet_pin):
    startup = packet.get("schema_version") == "task13-e-timing-pool-pending-v3"
    require(
        packet["schema_version"]
        == (
            "task13-e-timing-pool-pending-v3"
            if startup
            else "task13-e-timing-pool-pending-v2"
        )
        and packet["quota"] == (STARTUP_COUNTS if startup else RECOVERY_COUNTS),
        "exact five-attempt recovery packet required",
    )
    summary = {
        "scope_packet": packet_pin,
        "source_commit": packet["source_commit"],
        "source_proposal": packet["source_proposal"],
        "model_proposal": packet["model_proposal"],
        "recovery_plan": packet["recovery_plan"],
        "quarantine_record": packet["quarantine_record"],
        "recovery_equivalence": {
            "full_execution_dtos": "完整保留于scope_packet原包的recovery_equivalence字段",
            "policy_pin": packet["recovery_equivalence"]["policy_pin"],
            "original_execution_canonical_sha256": canonical_hash(
                packet["recovery_equivalence"]["original_execution"]
            ),
            "candidate_execution_canonical_sha256": canonical_hash(
                packet["recovery_equivalence"]["candidate_execution"]
            ),
        },
        "pool_proposal_sha256": packet["pool_proposal_sha256"],
        "data_scope": packet["data_scope"],
        "endpoint": packet["endpoint"],
        "quota": packet["quota"],
        "deadline": packet["deadline"],
        "development_cap_cny": 6,
        "actual_spent_cny": packet["actual_spent_cny"],
        "individual_actual_plan_approval": True,
        "new_analysis": False,
        "formal176": False,
        "F8": False,
    }
    question = (
        "是否批准以下具体人工审计恢复范围及新source/model元数据登记？"
        + (
            "旧池unknown及原记录保留，仅迁移原剩余4次逻辑规划/最多12次物理请求，"
            if startup
            else "旧池unknown及原记录保留，仅迁移原剩余5次逻辑规划/最多15次物理请求，"
        )
        + "不增加额度；C10原成绩须按本包等价核验使用。复用原合格分析，"
        "每份实际计划仍单独批准；不批准新分析、续期、正式176或F8。\n"
        + json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )
    return {
        "schema_version": _schema("prepared-question", startup),
        "record_kind": "prepared_question_not_user_consent",
        "scope_packet": packet_pin,
        "question": question,
        "approved_answer": "批准具体人工恢复范围（packet SHA256="
        + packet_pin["sha256"]
        + "）",
        "actual_user_reply": None,
        "automatic_approval": False,
    }


def derive_decision(request, chat, packet_pin, chat_pin):
    from scripts.task13_e_trial import SCOPE

    try:
        require(
            set(request)
            == {
                "schema_version",
                "scope_packet",
                "prepared_question",
                "question_item_id",
            }
            and request["schema_version"] == "task13-pool-question-delivery-v1"
            and request["scope_packet"] == packet_pin,
            "exact actual recovery question delivery required",
        )
        prepared = prepared_scope_question(read(packet_pin), packet_pin)
        require(
            read(request["prepared_question"]) == prepared,
            "frozen recovery question differs",
        )
        require(
            chat.get("role") == "user"
            and chat.get("source") == "actual_current_send_user_message_question_reply"
            and chat.get("question_reply")
            == [
                {
                    "questionItemId": request["question_item_id"],
                    "question": prepared["question"],
                    "answer": prepared["approved_answer"],
                }
            ],
            "actual reply must approve this concrete recovery packet",
        )
        item = json.loads(request["question_item_id"])
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
            "decision": "approved",
            "scope_packet_sha256": packet_pin["sha256"],
            "decided_at": chat["captured_at"],
            "record_id": "actual-current-chat/" + chat_pin["sha256"],
            "text": prepared["question"] + "\n" + prepared["approved_answer"],
            "question": prepared["question"],
            "answer": prepared["approved_answer"],
            "question_item_id": request["question_item_id"],
            "actual_chat_evidence": chat_pin,
            "authorization_request": request,
            "plan_approval_credit": 0,
            "formal176_scope": False,
            "f8_scope": False,
        }
    except (KeyError, ValueError, OSError, TypeError) as error:
        raise PermissionError("invalid concrete recovery reply") from error


def committed_recovery_source(tree, commit, original_receipt_pin):
    """Export every worker file; permission to change controls is not equivalence."""
    from scripts.task13_worker_runtime import EXPORT_PATHS

    tree = plain(tree, exists=False)
    require(
        tree == Path(__file__).resolve().parents[1],
        "run compiler from frozen evaluated tree",
    )
    require(re.fullmatch("[0-9a-f]{40}", commit), "full committed source required")
    require(
        original_receipt_pin["sha256"] == ORIGINAL_WORKER_RECEIPT,
        "original117 anchor differs",
    )
    old = read(original_receipt_pin)["files"]

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=tree, check=True, capture_output=True
        ).stdout

    require(git("rev-parse", "HEAD").decode().strip() == commit, "source HEAD differs")
    require(
        not git("status", "--porcelain", "--untracked-files=all").strip(),
        "evaluated tree must be clean",
    )
    archive = git("archive", "--format=zip", commit, *EXPORT_PATHS)
    files = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for item in bundle.infolist():
            if item.is_dir():
                continue
            require(
                (item.external_attr >> 16) & 0o170000 != 0o120000,
                "worker export contains link",
            )
            require(
                not Path(item.filename).is_absolute()
                and ".." not in Path(item.filename).parts,
                "worker export escapes",
            )
            files[item.filename] = bundle.read(item)
    hashes = {name: sha256(value).hexdigest() for name, value in files.items()}
    require(
        len(hashes) == 117 and set(hashes) == set(old),
        "complete original117 inventory required",
    )
    require(
        {name for name in hashes if hashes[name] != old[name]}
        <= AUTHORIZATION_WORKER_FILES,
        "worker business bytes changed",
    )
    for name, digest in hashes.items():
        require(
            pin(tree / name)["sha256"] == digest,
            "working worker bytes differ from commit",
        )
    return files, {
        "source_commit": commit,
        "archive_sha256": sha256(archive).hexdigest(),
        "files": hashes,
    }


def build_limited_children(
    source,
    model,
    core,
    old_planning,
    lineage,
    source_files,
    root,
    *,
    grant_base,
    packet_pin=None,
    decision_pin=None,
    decided_at=None,
):
    """Build native registrations first, then the shared 3+2 grant and authorities."""
    from evals.adapters.e_planning_journal import (
        LimitedEPlanningAuthority,
        ManualRecoveryGrant,
        StartupLimitedEPlanningAuthority,
        StartupRecoveryGrant,
    )
    from evals.e_planning import planning_requests
    from evals.e_timing import build_e_timing_registration

    startup = grant_base["schema_version"] == "task13-manual-startup-recovery-grant-v1"
    require(
        grant_base["schema_version"]
        in {
            "task13-manual-recovery-grant-v1",
            "task13-manual-startup-recovery-grant-v1",
        },
        "explicit grant schema required",
    )
    child_limit = 1 if startup else 2
    children, binding = build_children(
        source,
        model,
        core,
        old_planning,
        lineage,
        source_files,
        root,
        packet_pin=packet_pin,
        decision_pin=decision_pin,
        decided_at=decided_at,
    )
    grant = deepcopy(grant_base)
    grant.update(
        scope_packet_sha256=packet_pin["sha256"] if packet_pin else ZERO,
        decision_record_sha256=decision_pin["sha256"] if decision_pin else ZERO,
        children=[],
    )
    for index, child in enumerate(children):
        timing = child["registration"]
        planning = timing["planning_registration"]
        hashes = [canonical_hash(q) for q in planning_requests(planning)]
        grant["children"].append(
            {
                "registration_sha256": canonical_hash(planning),
                "journal_path": timing["planning_dispatch_registration_receipt"][
                    "journal_path"
                ],
                "request_sha256s": hashes,
                "authorized_request_sha256s": hashes
                if index == 0
                else hashes[:child_limit],
                "denied_request_sha256s": [] if index == 0 else hashes[child_limit:],
            }
        )
    if packet_pin:
        (StartupRecoveryGrant if startup else ManualRecoveryGrant).model_validate(grant)
    for child, child_grant in zip(children, grant["children"], strict=True):
        original = child.pop("authority")
        authority = None
        dispatch = deepcopy(
            child["registration"]["planning_dispatch_registration_receipt"]
        )
        if packet_pin:
            authority = {
                **original,
                "schema_version": "task13-e-planning-authority-v3"
                if startup
                else "task13-e-planning-authority-v2",
                "authorized_request_sha256s": child_grant["authorized_request_sha256s"],
                "denied_request_sha256s": child_grant["denied_request_sha256s"],
                "migration_grant": grant,
                "migration_grant_sha256": canonical_hash(grant),
            }
            (
                StartupLimitedEPlanningAuthority
                if startup
                else LimitedEPlanningAuthority
            ).model_validate(authority)
            dispatch["authority_sha256"] = canonical_hash(authority)
        child["registration"] = build_e_timing_registration(
            child["registration"]["planning_registration"],
            source_files=source_files,
            f8_plan_sha256=core["f8_plan_sha256"],
            planning_dispatch_registration_receipt=dispatch,
        )
        child["authority"] = authority
    return children, binding, grant


def compile_draft(
    p,
    predecessor,
    *,
    root,
    tree,
    commit,
    identity,
    source_receipt,
    worker_bytes,
    host_files,
    predecessor_materialization,
    predecessor_preparation,
    profile="manual-v2",
):
    """Pure inert construction. No native registration or execution journal."""
    from scripts.task13_pool_prepare import refs

    require(re.fullmatch("[0-9a-f]{32}", identity), "fixed recovery identity required")
    startup = _profile(profile)
    root, tree = Path(root), Path(tree)
    docs = Documents(root)
    old_source, old_model = predecessor["source"], predecessor["model"]
    require(
        old_source["epoch_number"] == (11 if startup else 10)
        and old_model["model_epoch_number"] == (8 if startup else 7),
        "exact stopped source10/model7 required",
    )
    require(
        len(source_receipt["files"]) == 117
        and set(worker_bytes) == set(source_receipt["files"]),
        "complete117 export required",
    )
    for name, digest in source_receipt["files"].items():
        require(
            sha256(worker_bytes[name]).hexdigest() == digest, "worker export differs"
        )
        docs.stage("source/" + name, worker_bytes[name])
    receipt_pin = docs.stage("source/source_receipt.json", source_receipt)
    core = recovery_core(p["core"], "model-manual-" + identity[:24], profile=profile)
    core_pin = docs.stage("core-config.json", core)
    entries = {}
    for name, digest in host_files.items():
        path = Path(name)
        relative = (
            str(path.relative_to(tree)).replace("\\", "/")
            if path.is_relative_to(tree)
            else next(
                (
                    key
                    for key, value in old_source["entrypoints"].items()
                    if value == digest
                    and str(path).replace("\\", "/").endswith("/" + key)
                ),
                None,
            )
        )
        require(
            relative is not None and relative not in entries,
            "full host relative inventory required",
        )
        entries[relative] = digest
    require(
        set(old_source["entrypoints"]) <= set(entries),
        "original full host inventory omitted",
    )
    controller = read(p["controller_manifest"])
    controller.update(
        source_commit=commit,
        entrypoints=entries,
        entrypoints_sha256=canonical_hash(entries),
    )
    controller_pin = docs.stage("controller-code-manifest.json", controller)
    roots = set(old_source["controller_state_roots"]) | {str(root / "pool-state")}
    if startup:
        roots.update(
            str(Path(f"D:/传智杯/.tmp/t13v3-{identity[:12]}-{i}")) for i in (1, 2)
        )
    for ordinal in (1, 2):
        roots.update(
            str(root / f"manual-{identity}-child-{ordinal}" / name)
            for name in (
                "host-output",
                "host-output/timing",
                "host-termination",
                "worker-output",
            )
        )
    source = deepcopy(old_source)
    source.update(
        epoch_id=("e12-manual-" if startup else "e11-manual-") + identity,
        epoch_number=old_source["epoch_number"] + 1,
        predecessor_epoch_id=old_source["epoch_id"],
        source_commit=commit,
        source_sha256=canonical_hash(source_receipt),
        config_sha256=canonical_hash(core),
        entrypoints=entries,
        entrypoints_sha256=canonical_hash(entries),
        controller_state_roots=sorted(roots),
        authority={
            "kind": "phase_scope_consent",
            "packet_sha256": None,
            "decision_record_sha256": None,
        },
    )
    source["runtime_binding"]["controller_manifest_sha256"] = controller_pin["sha256"]
    model = deepcopy(old_model)
    model.update(
        model_epoch_id=core["model_identity"]["id"],
        model_epoch_number=old_model["model_epoch_number"] + 1,
        predecessor_model_epoch_id=old_model["model_epoch_id"],
        epoch_id=source["epoch_id"],
        source_sha256=source["source_sha256"],
        config_sha256=source["config_sha256"],
        source_manifest_sha256=None,
        adoption_decision_sha256=None,
        controller_state_roots=source["controller_state_roots"],
        expected_model=core["model_identity"],
    )
    lineage = deepcopy(p["lineage"])
    lineage.update(
        recovery_id="manual-" + identity,
        execution_core_config_sha256=canonical_hash(core),
        execution_epoch_binding={
            "epoch_id": source["epoch_id"],
            "source_commit": commit,
            "source_sha256": source["source_sha256"],
            "budget_identity": source["budget_identity"],
            "model_epoch_id": model["model_epoch_id"],
        },
    )
    lineage_pin = docs.stage("recovery-lineage.json", lineage)
    plan = {
        "schema_version": _schema("plan", startup),
        "recovery_id": identity,
        "predecessor_materialization": predecessor_materialization,
        "predecessor_preparation": predecessor_preparation,
        "predecessor_pool_host": predecessor["pool_host_manifest"],
        "predecessor_head_sha256": "39be936e93a21e627e33deb4d8b8cbc215379b3629454cefb697fe1f454b0bf5"
        if startup
        else PREDECESSOR_HEAD,
        "source_commit": commit,
        "source_tree": str(tree),
        "source_epoch_id": source["epoch_id"],
        "model_epoch_id": model["model_epoch_id"],
        "source_receipt": receipt_pin,
        "controller_manifest": controller_pin,
        "core_config": core_pin,
        "recovery_lineage": lineage_pin,
        "quota": STARTUP_COUNTS if startup else RECOVERY_COUNTS,
        "deadline": DEADLINE,
        "development_cap_cny": 6,
        "actual_authority": None,
        "provider_requests": 0,
        "timing_credit": 0,
    }
    if startup:
        plan["temporary_roots"] = [
            f"D:/传智杯/.tmp/t13v3-{identity[:12]}-{i}" for i in (1, 2)
        ]
    plan_pin = docs.stage("recovery-plan.json", plan)
    preservation = {
        r["path"]: r
        for r in [
            *p["preservation"],
            *refs(predecessor),
            predecessor_materialization,
            predecessor_preparation,
        ]
    }
    value = {
        "schema_version": _schema("draft", startup),
        "status": "inert_no_authority",
        "recovery_plan": plan_pin,
        "source": source,
        "model": model,
        "core": core,
        "lineage": lineage,
        "old_planning": p["old_planning"],
        "old_runtime": p["old_runtime"],
        "old_host": p["old_host"],
        "pool_template": predecessor["pool"],
        "scope_template": read(p["scope_packet"]),
        "source_files": host_files,
        "controller_manifest": controller_pin,
        "source_receipt": receipt_pin,
        "preservation": list(preservation.values()),
        "database_snapshots": {},
        "actual_authority_created": 0,
        "provider_requests": 0,
    }
    docs.stage(
        "activation/source-epoch-proposal.json",
        {"registrable": False, "manifest_template": source},
    )
    docs.stage(
        "activation/model-identity-proposal.json",
        {"registrable": False, "manifest_template": model},
    )
    return docs, docs.stage("activation/draft-receipt.json", value)


def require_unclaimed_limited_child(child):
    """Read all structural slots directly; denied validation must fail closed."""
    import sqlite3

    from evals.adapters.e_planning_journal import EPlanningDispatchJournal, _read
    from evals.e_planning import planning_requests

    planning, authority = child["planning"], child["authority"]
    path = Path(authority["journal_path"])
    if not path.exists():
        return False
    native = EPlanningDispatchJournal.open_existing(
        path,
        expected_registration_sha256=canonical_hash(planning),
        expected_authority_sha256=canonical_hash(authority),
    )
    with sqlite3.connect(plain(path).as_uri() + "?mode=ro", uri=True) as db:
        _read(db, canonical_hash(planning), canonical_hash(authority))
        require(
            db.execute(
                "SELECT count(*) FROM analysis_import_planning_claims"
            ).fetchone()[0]
            == 0,
            "new native slot claimed; metadata reconciliation forbidden",
        )
    for request in planning_requests(planning):
        if canonical_hash(request) in authority["denied_request_sha256s"]:
            try:
                native.validate_request(request)
            except PermissionError:
                continue
            raise PermissionError("denied sixth request unexpectedly authorized")
        require(
            native.validate_request(request)["status"] == "unclaimed",
            "new native slot claimed",
        )
    return True


def compile_preparation(
    draft, draft_pin, *, quarantine_pin, equivalence, acceptance_pin, free_policy
):
    """Construct the concrete pending question in memory from audited materials."""
    from evals.timing_pool_controller import pool_scope_proposal
    from scripts.task13_pool_prepare import refs

    startup = _startup_schema(draft.get("schema_version"), "draft")
    p = deepcopy(draft)
    root = Path(draft_pin["path"]).parent.parent
    docs = Documents(root)
    plan = read(p["recovery_plan"])
    require(
        plan["schema_version"] == _schema("plan", startup), "draft/plan version differs"
    )
    old_host = read(plan["predecessor_pool_host"])
    quarantine = read(quarantine_pin)
    old_journal = quarantine["parent_journal"]
    predecessor = {
        "pool_registration": old_host["pool_registration"],
        "pool_journal": {key: old_journal[key] for key in ("path", "sha256")},
        "pool_head_sha256": old_journal["head_sha256"],
        "quarantine_record": quarantine_pin,
    }
    grant_base = {
        "schema_version": _schema("grant", startup),
        "recovery_id": plan["recovery_id"],
        "recovery_plan_sha256": p["recovery_plan"]["sha256"],
        "quarantine_record_sha256": quarantine_pin["sha256"],
        "predecessor_pool_registration_sha256": predecessor["pool_registration"][
            "sha256"
        ],
        "predecessor_pool_journal_sha256": predecessor["pool_journal"]["sha256"],
        "predecessor_pool_head_sha256": predecessor["pool_head_sha256"],
        "consumed_logical": 9 if startup else 8,
        "consumed_physical": 27 if startup else 24,
        "remaining_logical": 4 if startup else 5,
        "remaining_physical": 12 if startup else 15,
        "total_logical_limit": 13,
        "total_physical_limit": 39,
        "analysis_inclusive_limit": 40,
        "development_cap_yuan": "6",
        "deadline": DEADLINE,
    }
    children, binding, grant = build_limited_children(
        p["source"],
        p["model"],
        p["core"],
        p["old_planning"],
        p["lineage"],
        p["source_files"],
        root,
        grant_base=grant_base,
    )
    for child in children:
        child.pop("authority")
    pool = deepcopy(p.pop("pool_template"))
    pool.update(
        schema_version="task13-e-timing-pool-registration-v3"
        if startup
        else "task13-e-timing-pool-registration-v2",
        future_logical_limit=4 if startup else 5,
        future_physical_limit=12 if startup else 15,
        children=children,
        recovery_plan=p["recovery_plan"],
        quarantine_record=quarantine_pin,
        quarantined_predecessor=predecessor,
        migration_grant=grant,
        migration_grant_sha256=canonical_hash(grant),
        recovery_equivalence=equivalence,
        measurement_root=plan["source_tree"],
        measurement_files=read(p["source_receipt"])["files"],
        free_admission=free_policy,
        execution_journal_path=str(root / "pool-state/pool-journal.jsonl"),
    )
    pool["identity"].update(
        source_commit=p["source"]["source_commit"],
        source_sha256=canonical_hash(p["source_files"]),
        config_sha256=canonical_hash(p["core"]),
    )
    pool["formal_binding"] = {key: binding[key] for key in pool["formal_binding"]}
    attempts = [
        {"child_id": c["child_id"], "trial_id": t["trial_id"]}
        for c in children
        for t in c["registration"]["trials"]
    ]
    allowed = 4 if startup else 5
    pool["attempt_order"], pool["denied_attempts"] = (
        attempts[:allowed],
        attempts[allowed:],
    )
    baseline = read(pool["original_account_baseline"])
    baseline["development_ledger"] = development_ledger(
        Path(p["source"]["budget_path"])
    )
    pool["original_account_baseline"] = docs.stage(
        "original-account-baseline.json", baseline
    )
    proposal = pool_scope_proposal(pool)
    scope = p.pop("scope_template")
    packet = {
        "schema_version": "task13-e-timing-pool-pending-v3"
        if startup
        else "task13-e-timing-pool-pending-v2",
        "status": "pending_actual_concrete_recovery_scope",
        "registrable": False,
        "actual_authority": None,
        "actual_scope_decision": None,
        "scope": scope["scope"],
        "deadline": DEADLINE,
        "source_commit": p["source"]["source_commit"],
        "source_tree": str(Path(__file__).resolve().parents[1]),
        "source_sha256": p["source"]["source_sha256"],
        "source_receipt": p["source_receipt"],
        "source_proposal": pin(root / "activation/source-epoch-proposal.json"),
        "model_proposal": pin(root / "activation/model-identity-proposal.json"),
        "controller_manifest": p["controller_manifest"],
        "core_config": pin(root / "core-config.json"),
        "core_config_sha256": canonical_hash(p["core"]),
        "recovery_lineage": p["lineage"],
        "recovery_lineage_sha256": canonical_hash(p["lineage"]),
        "recovery_plan": p["recovery_plan"],
        "quarantine_record": quarantine_pin,
        "recovery_equivalence": equivalence,
        "participation_policy": p["core"]["participation_policy"],
        "pool_proposal": proposal,
        "pool_proposal_sha256": canonical_hash(proposal),
        "free_acceptance": acceptance_pin,
        "quota": STARTUP_COUNTS if startup else RECOVERY_COUNTS,
        "data_scope": scope["data_scope"],
        "endpoint": scope["endpoint"],
        "qualified_original_analysis": scope["qualified_original_analysis"],
        "actual_spent_cny": baseline["development_ledger"]["spent_yuan"],
        "automatic_plan_approval": False,
        "actual_individual_plan_approval_required": True,
        "no_new_analysis": True,
        "no_renewal": True,
        "formal176_scope": False,
        "f8_scope": False,
        "provider_requests": 0,
        "plan_approval_credit": 0,
    }
    packet_pin = docs.stage("scope-packet.json", packet)
    p.update(
        schema_version=_schema("preparation", startup),
        status="pending_no_authority_or_registration",
        draft=draft_pin,
        scope_packet=packet_pin,
        pool=pool,
        grant_base=grant_base,
        prepared_question=docs.stage(
            "activation/prepared-scope-question.json",
            prepared_scope_question(packet, packet_pin),
        ),
    )
    preservation = {
        ref["path"]: ref
        for ref in [
            *p["preservation"],
            draft_pin,
            p["recovery_plan"],
            quarantine_pin,
            acceptance_pin,
            *refs(equivalence),
            *refs(free_policy),
        ]
    }
    p["preservation"] = list(preservation.values())
    return docs, docs.stage("activation/preparation-receipt.json", p)


def validate_actual_scope_review(review, spec, preparation):
    startup = _startup_schema(
        preparation.get("schema_version", _schema("preparation")), "preparation"
    )
    require(
        isinstance(review, dict)
        and review.get("schema_version") == _schema("actual-scope-review", startup)
        and review.get("status") == "passed"
        and review.get("review_kind") == "independent_actual_scope"
        and isinstance(review.get("reviewer_identity"), str)
        and bool(review["reviewer_identity"].strip())
        and type(review.get("critical")) is int
        and review["critical"] == 0
        and type(review.get("important")) is int
        and review["important"] == 0
        and all(
            review.get(k) == spec[k]
            for k in ("preparation", "authorization_request", "actual_scope_chat")
        )
        and all(
            review.get(k) == preparation[k]
            for k in ("scope_packet", "controller_manifest")
        ),
        "independent actual scope review must bind exact freeze, preparation, delivery and incoming reply",
    )
    return review


def _latest(source, model):
    from scripts.task13_pool_prepare import require_native_prefix

    require_native_prefix(
        Path(source["budget_path"]), {"source": source, "model": model}, (True, True)
    )


def draft(spec):
    """Export a clean committed worker and fix an independent no-authority plan."""
    from evals.freeze import required_freeze_files
    from scripts.task13_pool_prepare import assert_preserved

    startup = _startup_schema(spec.get("schema_version"), "draft-spec")
    require(
        spec.get("schema_version") == _schema("draft-spec", startup),
        "explicit draft schema required",
    )
    root = plain(spec["candidate_output"], exists=False)
    require(not root.exists(), "exclusive new draft candidate required")
    m, old = (
        read(spec["predecessor_materialization"]),
        read(spec["predecessor_preparation"]),
    )
    require(
        m["preparation"] == spec["predecessor_preparation"],
        "predecessor preparation differs",
    )
    from evals.timing_pool_recovery import FROZEN

    if startup:
        from evals.timing_pool_startup_recovery import STARTUP_FROZEN

        frozen = STARTUP_FROZEN
    else:
        frozen = FROZEN
    if startup:
        require(
            spec["predecessor_materialization"]["sha256"] == frozen["materialization"]
            and spec["predecessor_preparation"]["sha256"] == frozen["preparation"],
            "exact startup predecessor materialization/preparation required",
        )

    require(
        m["pool_host_manifest"]["sha256"] == frozen["pool_host_manifest"]
        and read(read(m["pool_host_manifest"])["pool_registration"]) == m["pool"],
        "exact stopped predecessor pool required",
    )
    _latest(m["source"], m["model"])
    files, receipt = committed_recovery_source(
        spec["source_tree"], spec["source_commit"], spec["original_worker_receipt"]
    )
    tree = Path(spec["source_tree"])
    names = set(required_freeze_files(tree)) | set(m["source"]["entrypoints"])
    host_files = {
        str(tree / name): pin(tree / name)["sha256"] for name in sorted(names)
    }
    for name in ("evals/e_timing.py", "evals/e_planning.py"):
        require(
            host_files[str(tree / name)] == m["source"]["entrypoints"][name],
            "native measurement bytes changed",
        )
    # The previous preparation's account predates the stopped paid attempt.
    # Preserve its raw evidence, but capture the present database as the new baseline.
    for ref in old["preservation"]:
        raw(ref)
    docs, result_pin = compile_draft(
        old,
        m,
        root=root,
        tree=tree,
        commit=spec["source_commit"],
        identity=spec["recovery_id"],
        source_receipt=receipt,
        worker_bytes=files,
        host_files=host_files,
        predecessor_materialization=spec["predecessor_materialization"],
        predecessor_preparation=spec["predecessor_preparation"],
        profile="startup-v3" if startup else "manual-v2",
    )
    value = json.loads(docs.values[Path(result_pin["path"])])
    value["database_snapshots"] = {
        str(Path(m["source"]["budget_path"])): snapshot(
            Path(m["source"]["budget_path"])
        )
    }
    for child in m["children"]:
        path = child["authority"]["journal_path"]
        value["database_snapshots"][path] = snapshot(path)
    docs.values[Path(result_pin["path"])] = encode(value)
    result_pin = pin(result_pin["path"], docs.values[Path(result_pin["path"])])
    assert_preserved(value)
    docs.publish()
    assert_preserved(value)
    return {
        "draft": result_pin,
        "recovery_plan": value["recovery_plan"],
        "status": value["status"],
        "provider_requests": 0,
    }


def prepare(spec):
    """Admit real frozen free review, independent quarantine and equivalence."""
    from evals.recovery_equivalence import validate_recovery_equivalence
    from evals.timing_pool_recovery import validate_quarantine_evidence
    from scripts.task13_pool_prepare import assert_preserved, refs

    startup = _startup_schema(spec.get("schema_version"), "prepare-spec")
    require(
        spec.get("schema_version") == _schema("prepare-spec", startup),
        "explicit preparation schema required",
    )
    p = read(spec["draft"])
    require(
        p["schema_version"] == _schema("draft", startup)
        and p["actual_authority_created"] == 0,
        "inert draft required",
    )
    assert_preserved(p)
    plan = read(p["recovery_plan"])
    _latest(
        read(plan["predecessor_materialization"])["source"],
        read(plan["predecessor_materialization"])["model"],
    )
    for name, digest in p["source_files"].items():
        require(pin(name)["sha256"] == digest, "frozen source drifted")
    committed_recovery_source(
        Path(__file__).resolve().parents[1],
        p["source"]["source_commit"],
        spec["original_worker_receipt"],
    )
    quarantine = read(spec["quarantine_record"])
    validate_quarantine_evidence(quarantine, expected_scope=p["recovery_plan"])
    eq = spec["recovery_equivalence"]
    require(
        set(eq) == {"original_execution", "candidate_execution", "policy_pin"},
        "complete independent equivalence required",
    )
    validate_recovery_equivalence(**eq)
    acceptance = read(spec["free_acceptance"])
    require(
        acceptance.get("source_commit") == p["source"]["source_commit"]
        and acceptance.get("status") == "passed"
        and type(acceptance.get("critical")) is int
        and acceptance["critical"] == 0
        and type(acceptance.get("important")) is int
        and acceptance["important"] == 0
        and acceptance.get("source_files_sha256") == canonical_hash(p["source_files"]),
        "actual free acceptance differs from frozen source",
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
        "complete free admission policy required",
    )
    root = Path(spec["draft"]["path"]).parent.parent
    require(
        plain(policy["gate_root"], exists=False).is_relative_to(root),
        "admission outputs must stay inside candidate",
    )
    helper = pin(
        Path(__file__).resolve().parents[1] / "scripts/task13_pool_admission.py"
    )
    require(
        policy["helpers"]
        == dict.fromkeys(("assembler", "native_probe", "services"), helper),
        "frozen native admission helpers required",
    )
    for ref in refs(policy):
        raw(ref)
    docs, result_pin = compile_preparation(
        p,
        spec["draft"],
        quarantine_pin=spec["quarantine_record"],
        equivalence=eq,
        acceptance_pin=spec["free_acceptance"],
        free_policy=policy,
    )
    compiled = json.loads(docs.values[Path(result_pin["path"])])
    from evals.timing_pool import (
        C10_EVIDENCE_ROOT,
        C10_IMPORT_PINS,
        C10_REGISTRATION,
        C10_TRIAL,
        read_native_observation,
        validate_recovery_equivalence_join,
    )

    require(
        compiled["pool"]["imported_observations"]
        == [
            {
                "evidence_root": str(C10_EVIDENCE_ROOT),
                "trial_id": C10_TRIAL,
                "registration_sha256": C10_REGISTRATION,
                **C10_IMPORT_PINS,
            }
        ],
        "only the independently audited original C10 can import",
    )
    original = read_native_observation(C10_EVIDENCE_ROOT, C10_TRIAL)
    validate_recovery_equivalence_join(compiled["pool"], original)
    assert_preserved(p)
    docs.publish()
    assert_preserved(p)
    return {
        "preparation": result_pin,
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
    from evals.timing_pool_controller import pool_scope_proposal
    from scripts.task13_e_trial import SCOPE
    from scripts.task13_timing_pool import derive_next_three_bound

    startup = _startup_schema(preparation.get("schema_version"), "preparation")
    require(read(preparation_pin) == preparation, "exact pinned preparation required")
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
    children, binding, grant = build_limited_children(
        source,
        model,
        p["core"],
        p["old_planning"],
        p["lineage"],
        p["source_files"],
        root,
        grant_base=p["grant_base"],
        packet_pin=packet_pin,
        decision_pin=decision_pin,
        decided_at=decision["decided_at"],
    )
    authorities = {child["child_id"]: child.pop("authority") for child in children}
    pool = deepcopy(p["pool"])
    pool["children"] = children
    pool["migration_grant"] = grant
    pool["migration_grant_sha256"] = canonical_hash(grant)
    pool["formal_binding"] = {key: binding[key] for key in pool["formal_binding"]}
    require(
        pool_scope_proposal(pool) == packet["pool_proposal"]
        and canonical_hash(packet["pool_proposal"]) == packet["pool_proposal_sha256"],
        "actual pool is not inverse of approved proposal",
    )
    pool_pin = docs.stage("activation/pool-registration.json", pool)
    hosts, materialized_children, bounds = {}, [], []
    for ordinal, child in enumerate(children, 1):
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
        if startup:
            plan = read(p["recovery_plan"])
            roots = [
                f"D:/传智杯/.tmp/t13v3-{plan['recovery_id'][:12]}-{i}" for i in (1, 2)
            ]
            require(
                plan.get("temporary_roots") == roots,
                "pinned owned temporary roots differ",
            )
            runtime["temporary_root"] = roots[ordinal - 1]
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
    marker_pin = pool["quarantine_record"]
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
        "schema_version": "task13-e-timing-pool-host-v3"
        if startup
        else "task13-e-timing-pool-host-v2",
        "pool_registration": pool_pin,
        "hosts": hosts,
        "journal_path": pool["execution_journal_path"],
        "original_account_baseline": pool["original_account_baseline"],
        "migration_marker": marker_pin,
        "capacity_proof": capacity_pin,
    }
    manifest_pin = docs.stage("activation/pool-host-manifest.json", manifest)
    materialization = {
        "schema_version": _schema("materialization", startup),
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


def _pool_genesis(pool):
    from evals.timing_pool import pool_policy
    from evals.timing_pool_controller import PoolJournal
    from scripts.task13_pool_prepare import initial_pool_spent

    path = Path(pool["execution_journal_path"])
    if not path.exists():
        return False
    events = PoolJournal(
        path, pool_sha256=canonical_hash(pool), policy=pool_policy(pool)
    )._events()
    expected = {
        "attempts": [a["trial_id"] for a in pool["attempt_order"]],
        "imported_trial_id": pool["imported_observations"][0]["trial_id"],
        "initial_spent_yuan": initial_pool_spent(pool),
        "imported_max_seconds": 384.562,
        "policy": pool["schema_version"],
        "migration_grant": pool["migration_grant"],
        "quarantined_predecessor": pool["quarantined_predecessor"],
    }
    require(
        len(events) == 1
        and events[0]["kind"] == "prepare"
        and events[0]["payload"] == expected,
        "pool execution or divergent genesis prevents metadata resume",
    )
    return True


def initialize_timing_genesis(child):
    """Append only native campaign metadata after rejecting execution prefixes."""
    from evals.e_timing import ETimingCampaign
    from scripts.task13_pool_prepare import require_timing_genesis

    if not require_timing_genesis(child):
        ETimingCampaign(child["registration"], child["evidence_root"])
    require_timing_genesis(child)


def require_inert_outputs(pool, *, lease=None):
    """No planning, read, decision, trial, worker or denied-slot artifacts."""
    owned = set()
    if lease is not None:
        import os

        from evals.timing_pool_recovery import _require_lease

        _require_lease(lease)
        roots = {
            plain(path, exists=False) for path in lease.spec["controller_state_roots"]
        }
        output_roots = set()
        for child in pool["children"]:
            timing = plain(child["evidence_root"], exists=False)
            output_roots.update(
                (
                    timing,
                    timing.parent,
                    timing.parent.parent / "worker-output",
                    timing.parent.parent / "host-termination",
                )
            )
        fences = {root / ".pool-adoption-fence" for root in roots}
        locks = {root / "host-writer.lock" for root in roots}
        require(
            output_roots <= roots
            and fences <= lease.owned.keys() <= fences | locks
            and {root / "host-writer.lock" for root in output_roots}
            <= lease.owned.keys(),
            "live recovery lease does not own the exact pool output roots",
        )
        owner_bytes = json.dumps({"pid": os.getpid(), "nonce": lease.nonce}).encode()
        for path, owner in lease.owned.items():
            require(
                isinstance(owner, tuple)
                if path in fences
                else isinstance(owner, bytes) and owner == owner_bytes,
                "native recovery metadata lock owner differs",
            )
        owned = set(lease.owned)
    for child in pool["children"]:
        timing = plain(child["evidence_root"], exists=False)
        host, base = timing.parent, timing.parent.parent
        for name in ("worker-output", "host-termination"):
            path = plain(base / name, exists=False)
            require(
                not path.exists()
                or path.is_dir()
                and all(entry in owned for entry in path.iterdir()),
                "native execution output prevents metadata-only recovery",
            )
        if not host.exists():
            continue
        for path in host.rglob("*"):
            plain(path, exists=False)
            if path in owned:
                continue
            relative = path.relative_to(host).as_posix()
            require(
                relative
                in {
                    "host-binding.json",
                    "timing",
                    "timing/registration.json",
                    "timing/events",
                }
                or re.fullmatch(r"timing/events/00000000-[0-9a-f]{64}\.json", relative),
                "planning or unknown native output prevents metadata-only recovery",
            )
    if lease is not None:
        _require_lease(lease)


def audit_registered_prefix(lease, budget, materialization, baseline, quarantine):
    """Fresh resume audit under authentic native locks, without appending rows."""
    import sqlite3
    from contextlib import ExitStack

    from evals.adapters.source_epochs import _lock_controller_roots
    from scripts.task13_pool_prepare import require_native_prefix, validate_epoch_prefix

    roots = materialization["source"]["controller_state_roots"]
    with ExitStack() as stack:
        owned_locks = _lock_controller_roots(roots, stack)
        with sqlite3.connect(budget, timeout=30) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            require(
                validate_epoch_prefix(baseline, snapshot(budget), materialization)
                == (True, True),
                "exact registered metadata prefix required",
            )
            require_native_prefix(budget, materialization, (True, True))
            lease.locked_audit(
                expected_evidence=quarantine,
                expected_target=materialization
                if materialization["pool"]["schema_version"]
                == "task13-e-timing-pool-registration-v3"
                else None,
            )(db=db, controller_state_roots=tuple(roots), owned_locks=owned_locks)


def adopt(spec, *, resume=False):
    """Use an exact actual recovery answer for metadata only, never execute plans."""
    from evals.adapters.e_planning_journal import register_planning_slots
    from evals.adapters.model_identities import register_model_identity
    from evals.adapters.source_epochs import register_source_epoch
    from evals.timing_pool import pool_policy, validate_pool_registration
    from evals.timing_pool_controller import PoolJournal
    from evals.timing_pool_recovery import (
        manual_recovery_quiescence,
        validate_quarantine_evidence,
    )
    from scripts.task13_pool_prepare import (
        adoption_marker,
        adoption_result,
        assert_preserved,
        initial_pool_spent,
        require_native_prefix,
        require_no_active_metadata_locks,
        require_timing_genesis,
        validate_epoch_prefix,
    )

    require(
        isinstance(spec, dict)
        and set(spec)
        == {
            "preparation",
            "authorization_request",
            "actual_scope_chat",
            "actual_scope_review",
        },
        "exact separately approved adoption inputs required; development permission is not scope authority",
    )
    require(
        type(resume) is bool and datetime.now(UTC) < datetime.fromisoformat(DEADLINE),
        "deadline elapsed or invalid resume mode",
    )
    p = read(spec["preparation"])
    startup = _startup_schema(p.get("schema_version"), "preparation")
    require(
        p.get("schema_version") == _schema("preparation", startup)
        and p.get("status") == "pending_no_authority_or_registration"
        and p.get("actual_authority_created") == 0,
        "inert original manual recovery preparation required",
    )
    validate_actual_scope_review(read(spec["actual_scope_review"]), spec, p)
    packet = read(p["scope_packet"])
    committed_recovery_source(
        packet["source_tree"],
        packet["source_commit"],
        p["pool"]["recovery_equivalence"]["original_execution"]["source_receipt_pin"],
    )
    for name, digest in p["source_files"].items():
        require(pin(name)["sha256"] == digest, "frozen host source changed")
    docs, m, materialization_pin = compile_adoption(
        p, spec["preparation"], spec["authorization_request"], spec["actual_scope_chat"]
    )
    validate_pool_registration(m["pool"])
    root = Path(spec["preparation"]["path"]).parent.parent
    budget = Path(m["source"]["budget_path"])
    assert_preserved(p, skip_budget=budget if resume else None)
    original_budget = p["database_snapshots"][str(budget)]
    prefix = validate_epoch_prefix(original_budget, snapshot(budget), m)
    require_native_prefix(budget, m, prefix)
    require(
        resume or prefix == (False, False),
        "epoch append already exists; explicit identical-authority resume required",
    )
    start = root / "activation/adoption-started.json"
    expected_start = adoption_marker(spec, materialization_pin)
    expected_start["schema_version"] = _schema("adoption-start", startup)
    if resume:
        require(
            start.exists() and read(pin(start)) == expected_start,
            "resume requires identical original authority and review",
        )
        docs.validate_existing()
    else:
        require(
            not start.exists() and not any(t.exists() for t in docs.values),
            "partial adoption exists; use exact explicit resume",
        )
    for child in m["children"]:
        present = require_unclaimed_limited_child(child)
        require(
            not present or prefix == (True, True),
            "child journal precedes source/model metadata",
        )
    require_inert_outputs(m["pool"])
    for child in m["pool"]["children"]:
        present = require_timing_genesis(child)
        require(
            not present
            or all(require_unclaimed_limited_child(c) for c in m["children"]),
            "timing metadata precedes native registrations",
        )
    pool_present = _pool_genesis(m["pool"])
    require(
        not pool_present
        or all(require_timing_genesis(c) for c in m["pool"]["children"]),
        "pool genesis precedes native timing genesis",
    )
    quarantine = read(m["pool"]["quarantine_record"])
    validate_quarantine_evidence(quarantine, expected_scope=p["recovery_plan"])
    roots = [Path(path) for path in m["source"]["controller_state_roots"]]
    require_no_active_metadata_locks(roots)
    for path in roots:
        plain(path, exists=False)
        if not path.exists():
            staging = set()
            if startup:
                plan = read(p["recovery_plan"])
                expected = [
                    f"D:/传智杯/.tmp/t13v3-{plan['recovery_id'][:12]}-{i}"
                    for i in (1, 2)
                ]
                require(
                    plan.get("temporary_roots") == expected,
                    "owned startup staging roots differ",
                )
                staging = {Path(value) for value in expected}
            require(
                path.is_relative_to(root) or path in staging,
                "cannot reconstruct missing historical or unpinned staging root",
            )
            path.mkdir(parents=True)
    marker = Documents(root)
    marker.stage("activation/adoption-started.json", expected_start)
    marker.publish_missing() if resume else marker.publish()
    lock_spec = {
        "schema_version": _schema("lock-spec", startup),
        "pool_host_manifest": quarantine["pool_host_manifest"],
        "expected_scope": p["recovery_plan"],
        "stop_evidence": quarantine["stop_evidence"],
        "fee_audit": quarantine["fee_audit"],
        "controller_state_roots": m["source"]["controller_state_roots"],
    }
    if resume and pool_present:
        lock_spec["target_pool_registration"] = read(m["pool_host_manifest"])[
            "pool_registration"
        ]
    with manual_recovery_quiescence(lock_spec) as lease:
        assert_preserved(p, skip_budget=budget)
        prefix = validate_epoch_prefix(original_budget, snapshot(budget), m)
        require_native_prefix(budget, m, prefix)
        for index, (name, register) in enumerate(
            (("source", register_source_epoch), ("model", register_model_identity))
        ):
            if not prefix[index]:
                value, authority = m[name], m[name + "_authority"]
                register(
                    budget,
                    value,
                    expected_manifest_sha256=canonical_hash(value),
                    budget_identity=m["source"]["budget_identity"],
                    authority=authority,
                    expected_authority_sha256=canonical_hash(authority),
                    locked_audit=lease.locked_audit(
                        expected_evidence=quarantine,
                        expected_target=m if startup else None,
                    ),
                )
        if prefix == (True, True):
            audit_registered_prefix(lease, budget, m, original_budget, quarantine)
        require(
            validate_epoch_prefix(original_budget, snapshot(budget), m) == (True, True),
            "exact source and model appends required",
        )
        require_native_prefix(budget, m, (True, True))
        registered_budget = snapshot(budget)
        for child in m["children"]:
            authority = child["authority"]
            path = Path(authority["journal_path"])
            require(path.is_relative_to(root), "new native journal escapes candidate")
            if not require_unclaimed_limited_child(child):
                path.parent.mkdir(parents=True, exist_ok=True)
                receipt = register_planning_slots(
                    path,
                    child["planning"],
                    expected_registration_sha256=canonical_hash(child["planning"]),
                    authority=authority,
                    expected_authority_sha256=canonical_hash(authority),
                )
                require(
                    receipt == child["dispatch"],
                    "native limited registration differs from compiled dispatch",
                )
            require_unclaimed_limited_child(child)
        docs.publish_missing() if resume else docs.publish()
        for child in m["pool"]["children"]:
            initialize_timing_genesis(child)
        require_inert_outputs(m["pool"], lease=lease)
        require(
            snapshot(budget) == registered_budget,
            "metadata initialization changed unrelated account rows",
        )
        assert_preserved(p, skip_budget=budget)
    # Standard parent publication takes its own native lock after the adoption
    # fences are released. Source/model retirement and the old STOP are durable.
    pool = m["pool"]
    if not _pool_genesis(pool):
        PoolJournal.prepare(
            pool["execution_journal_path"],
            pool_sha256=canonical_hash(pool),
            attempts=[a["trial_id"] for a in pool["attempt_order"]],
            imported_trial_id=pool["imported_observations"][0]["trial_id"],
            now=datetime.now(UTC),
            initial_spent_yuan=initial_pool_spent(pool),
            imported_max_seconds=384.562,
            policy=pool_policy(pool),
            migration_grant=pool["migration_grant"],
            quarantined_predecessor=pool["quarantined_predecessor"],
        )
    _pool_genesis(pool)
    require(
        snapshot(budget) == registered_budget,
        "parent metadata publication changed account rows",
    )
    assert_preserved(p, skip_budget=budget)
    result = adoption_result(m, materialization_pin)
    result["schema_version"] = _schema("adoption-result", startup)
    result["new_unclaimed_logical_slots"] = pool_policy(pool).future_logical_limit
    result["denied_structural_slots"] = len(pool["denied_attempts"])
    result_docs = Documents(root)
    result_pin = result_docs.stage("activation/adoption-result.json", result)
    result_docs.publish_missing() if resume else result_docs.publish()
    return {"result": result_pin, **result}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation", choices=("draft", "prepare", "adopt", "resume-adoption")
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--input-sha256", required=True)
    args = parser.parse_args(argv)
    spec = read({"path": str(args.input), "sha256": args.input_sha256})
    if args.operation == "draft":
        result = draft(spec)
    elif args.operation == "prepare":
        result = prepare(spec)
    else:
        result = adopt(spec, resume=args.operation == "resume-adoption")
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
