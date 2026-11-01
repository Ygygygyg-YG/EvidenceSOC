"""Explicit SYNTHETIC metadata fixture, never production adoption.

All writes stay beneath the supplied pytest directory. Original native files are
read only. The caller owns the copied SQLite namespace and native registration;
this helper never registers an epoch or acquires any original controller lock.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from evals.freeze import required_freeze_files
from evals.timing_pool import C10_EVIDENCE_ROOT
from scripts.task13_pool_prepare import (
    MATERIALIZATION_SHA,
    Documents,
    compile_adoption,
    compile_pending,
    development_ledger,
    pin,
    read,
)


def original_templates():
    old_root = C10_EVIDENCE_ROOT.parent.parent
    ref = {
        "path": str(old_root / "activation/materialization.json"),
        "sha256": MATERIALIZATION_SHA,
    }
    m = read(ref)
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
    data.update(
        receipt=read(pin(old_root / "source/source_receipt.json")),
        host=read(pin(old_root / "activation/host-manifest.json")),
        old_root=old_root,
        materialization_pin=ref,
        preservation=[],
        database_snapshots={},
    )
    return data


def compile_fixture_documents(
    tmp_path,
    actual_conditions,
    *,
    data_override=None,
    baseline=None,
    free_policy=None,
    publish_adoption=True,
):
    """Publish test metadata only; a caller may rebase inputs into its copied DB.

    ``data_override`` is a complete copied/rebased original_templates() result.
    The source export uses the real original commit/117 map; changed control files
    are independently frozen in the current full host inventory.
    """
    data = deepcopy(
        data_override if data_override is not None else original_templates()
    )
    tree = Path(__file__).resolve().parents[2]
    root = Path(tmp_path).absolute() / "SYNTHETIC-pool-metadata-never-production"
    data["observation"] = {"actual_conditions": deepcopy(actual_conditions)}
    baseline = deepcopy(baseline or {})
    baseline["development_ledger"] = development_ledger(data["source"]["budget_path"])
    files = {
        name: (data["old_root"] / "source" / name).read_bytes()
        for name in data["receipt"]["files"]
    }
    names = set(required_freeze_files(tree)) | set(data["source"]["entrypoints"])
    host_files = {
        str(tree / name): pin(tree / name)["sha256"] for name in sorted(names)
    }
    docs, preparation_pin = compile_pending(
        data,
        root=root,
        tree=tree,
        commit=data["receipt"]["source_commit"],
        identity="6" * 32,
        source_receipt=data["receipt"],
        worker_bytes=files,
        host_files=host_files,
        free_policy=free_policy or {},
        acceptance_pin={"SYNTHETIC_TEST_ONLY": True},
        baseline=baseline or {},
    )
    preparation = json.loads(docs.values[Path(preparation_pin["path"])])
    docs.publish()
    incoming = Documents(root)
    prepared = read(preparation["prepared_question"])
    question = {
        "schema_version": "task13-pool-question-delivery-v1",
        "scope_packet": preparation["scope_packet"],
        "prepared_question": preparation["prepared_question"],
        "question_item_id": '["request_user_input_async","SYNTHETIC-COW",0]',
    }
    chat = {
        "role": "user",
        "source": "actual_current_send_user_message_question_reply",
        "captured_at": "2026-11-01T01:00:00+00:00",
        "question_reply": [
            {
                "questionItemId": question["question_item_id"],
                "question": prepared["question"],
                "answer": prepared["approved_answer"],
            }
        ],
    }
    request_pin = incoming.stage("SYNTHETIC-question.json", question)
    chat_pin = incoming.stage("SYNTHETIC-chat.json", chat)
    incoming.publish()
    adopted, materialization, materialization_pin = compile_adoption(
        preparation, preparation_pin, request_pin, chat_pin
    )
    if publish_adoption:
        adopted.publish()
    return {
        "root": root,
        "data": data,
        "preparation": preparation,
        "preparation_pin": preparation_pin,
        "materialization": materialization,
        "materialization_pin": materialization_pin,
        "adoption_documents": adopted,
        "request_pin": request_pin,
        "chat_pin": chat_pin,
    }
