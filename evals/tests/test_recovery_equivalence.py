"""Synthetic, free-only checks; no real policy review or native evidence writes."""

import ast
import json
from copy import deepcopy
from hashlib import sha256
from importlib import import_module, util
from pathlib import Path

import pytest

from evals.contracts import canonical_hash
from evals.e_timing import BOOTSTRAP, ORDER


def module():
    assert util.find_spec("evals.recovery_equivalence"), "recovery equivalence missing"
    return import_module("evals.recovery_equivalence")


def digest(value):
    return sha256(value).hexdigest()


def ast_hash(source):
    return digest(
        ast.dump(ast.parse(source).body[0], include_attributes=False).encode()
    )


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return {"path": str(path), "sha256": digest(path.read_bytes())}


@pytest.fixture
def example(tmp_path, monkeypatch):
    m = module()
    old, new = tmp_path / "original", tmp_path / "candidate"
    name = "evals/adapters/e_planning_journal.py"
    before = "def authority():\n    return 'v1'\n\ndef business():\n    return 1800\n"
    after = before.replace("return 'v1'", "return 'limited-v2'")
    files = {name: before, "evals/e_planning.py": "TTL = 1800\n"}
    files.update({f"worker/file_{i}.py": f"VALUE = {i}\n" for i in range(115)})
    native = {
        "evals/e_timing.py": "TIMEOUT = 180\n",
        "evals/e_planning.py": files["evals/e_planning.py"],
        "evals/verification.py": "ORDER = 6\n",
        "evals/verification_v2.py": "VALIDATION = True\n",
        "scripts/task13_e_trial.py": "CONTROLLER = True\n",
    }
    for root in (old, new):
        for relative, value in {**files, **native}.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value.encode())
    (new / name).write_bytes(after.encode())
    original_files = {k: digest(v.encode()) for k, v in files.items()}
    candidate_files = {**original_files, name: digest(after.encode())}
    native_files = {k: digest(v.encode()) for k, v in native.items()}
    receipt = write_json(old / "source_receipt.json", {"files": original_files})
    # Only the original manifest trust anchor is replaced for this synthetic fixture.
    monkeypatch.setattr(m, "ORIGINAL_SOURCE_RECEIPT_SHA256", receipt["sha256"])
    original = {
        "root": str(old),
        "source_receipt_pin": receipt,
        "measurement_files": original_files,
        "native_measurement_files": native_files,
        "identity": {
            "source": {"id": "source-9"},
            "model": {"id": "model-6"},
            "controller": {"id": "old-controller"},
        },
        "core_config": {"plan_ttl_seconds": 1800, "model": {"temperature": 0}},
        "disclosed_control_changes": {},
        "candidate_conditions": {
            "received_model": {
                "response_model": "synthetic",
                "fingerprint": "synthetic",
            },
            "image_id": "sha256:synthetic",
            "dependencies_lock_sha256": "a" * 64,
            "dependencies_tree_sha256": "b" * 64,
            "knowledge_sha256": "c" * 64,
        },
        "measurement_constants": {
            "bootstrap": BOOTSTRAP,
            "order": [list(x) for x in ORDER],
        },
        "runtime_conditions": {
            "budget": {"limit": 6},
            "plan_ttl_seconds": 1800,
            "timeouts": {"branch": 180, "total": 1200},
            "seed": None,
            "clock": "wall-and-monotonic",
            "branch_order": [list(x) for x in ORDER],
        },
    }
    candidate = deepcopy(original)
    candidate.pop("source_receipt_pin")
    candidate.update(root=str(new), measurement_files=candidate_files)
    candidate["identity"] = {
        "source": {"id": "source-11"},
        "model": {"id": "model-8"},
        "controller": {"id": "new-controller"},
    }
    policy = {
        "schema_version": "task13-recovery-equivalence-policy-v1",
        "review": {"status": "reviewed", "review_record_sha256": "d" * 64},
        "original_source_receipt_sha256": receipt["sha256"],
        "original_measurement_files": original_files,
        "candidate_measurement_files": candidate_files,
        "original_native_measurement_files": native_files,
        "candidate_native_measurement_files": native_files,
        "original_binding_sha256": canonical_hash(
            {k: v for k, v in original.items() if k != "root"}
        ),
        "candidate_binding_sha256": canonical_hash(
            {k: v for k, v in candidate.items() if k != "root"}
        ),
        "changes": {
            name: {
                "before_sha256": original_files[name],
                "after_sha256": candidate_files[name],
                "nodes": {
                    "function:authority": {
                        "before_sha256": ast_hash(
                            "def authority():\n    return 'v1'\n"
                        ),
                        "after_sha256": ast_hash(
                            "def authority():\n    return 'limited-v2'\n"
                        ),
                    }
                },
            }
        },
    }
    pin = write_json(tmp_path / "synthetic-policy.json", policy)
    # Synthetic review IO seam; production registry intentionally remains empty.
    monkeypatch.setattr(
        m,
        "REVIEWED_RECOVERY_POLICIES",
        frozenset({m.review_policy_fingerprint(policy)}),
    )
    return m, original, candidate, policy, pin, name


def repin(example, *, review=True):
    m, old, new, policy, pin, _ = example
    policy["candidate_binding_sha256"] = canonical_hash(
        {k: v for k, v in new.items() if k != "root"}
    )
    policy.update(
        original_source_receipt_sha256=m.ORIGINAL_SOURCE_RECEIPT_SHA256,
        original_measurement_files=old["measurement_files"],
        candidate_measurement_files=new["measurement_files"],
        original_native_measurement_files=old["native_measurement_files"],
        candidate_native_measurement_files=new["native_measurement_files"],
    )
    updated = write_json(Path(pin["path"]), policy)
    pin.update(updated)
    if review:
        m.REVIEWED_RECOVERY_POLICIES = frozenset({m.review_policy_fingerprint(policy)})


def test_reviewed_exact_change_keeps_all_raw_hashes_and_native_identity(example):
    m, old, new, _, pin, name = example
    proof = m.validate_recovery_equivalence(old, new, pin)
    assert proof["scope"] == "source-and-declared-conditions-only"
    assert proof["timing_credit"] is False and proof["authorization"] is False
    assert proof["original_identity"] == old["identity"]
    assert proof["candidate_identity"] == new["identity"]
    assert proof["original_measurement_files"] == old["measurement_files"]
    assert proof["candidate_measurement_files"] == new["measurement_files"]
    assert proof["native_measurement_files"] == old["native_measurement_files"]
    assert proof["changed_files"] == [name]


@pytest.mark.parametrize(
    "forgery", ["unregistered", "changed-bytes", "no-review", "fake-dict"]
)
def test_policy_cannot_be_self_authorized(example, forgery):
    m, old, new, policy, pin, _ = example
    if forgery == "unregistered":
        m.REVIEWED_RECOVERY_POLICIES = frozenset()
    elif forgery == "changed-bytes":
        Path(pin["path"]).write_text("{}")
    elif forgery == "no-review":
        policy["review"]["status"] = "draft"
        repin(example)
    else:
        pin = policy
    with pytest.raises(PermissionError):
        m.validate_recovery_equivalence(old, new, pin)


@pytest.mark.parametrize(
    "tamper",
    [
        "business-node",
        "node-hash",
        "missing-file",
        "extra-file",
        "native-code",
        "same-name-other-file",
        "unlisted-control",
        "protected-constants",
        "model-drift",
        "config-drift",
        "runtime-drift",
        "missing-runtime-field",
        "empty-native",
        "unlisted-import",
        "missing-identity",
        "runtime-type-drift",
        "config-type-drift",
    ],
)
def test_all_unreviewed_or_semantically_incompatible_differences_rejected(
    example, tamper
):
    from pathlib import Path

    m, old, new, policy, pin, name = example
    path = Path(new["root"]) / name
    if tamper in {"business-node", "protected-constants", "unlisted-import"}:
        raw = (
            path.read_bytes().replace(b"return 1800", b"return 1799")
            if tamper == "business-node"
            else path.read_bytes()
            + (b"DRIFT = 1\n" if tamper == "protected-constants" else b"import os\n")
        )
        path.write_bytes(raw)
        new["measurement_files"][name] = digest(raw)
        policy["changes"][name]["after_sha256"] = digest(raw)
    elif tamper == "node-hash":
        policy["changes"][name]["nodes"]["function:authority"]["after_sha256"] = (
            "0" * 64
        )
    elif tamper == "missing-file":
        new["measurement_files"].pop("worker/file_0.py")
    elif tamper == "extra-file":
        new["measurement_files"]["worker/extra.py"] = "a" * 64
    elif tamper == "native-code":
        native = Path(new["root"]) / "evals/e_timing.py"
        native.write_bytes(b"TIMEOUT = 181\n")
        new["native_measurement_files"]["evals/e_timing.py"] = digest(
            native.read_bytes()
        )
    elif tamper == "same-name-other-file":
        target = "worker/file_0.py"
        target_path = Path(new["root"]) / target
        target_path.write_bytes(b"def authority():\n    return 'limited-v2'\n")
        new["measurement_files"][target] = digest(target_path.read_bytes())
        policy["changes"][target] = policy["changes"].pop(name)
    elif tamper == "unlisted-control":
        policy["changes"] = {}
    elif tamper == "model-drift":
        new["candidate_conditions"]["received_model"]["fingerprint"] = "changed"
    elif tamper == "config-drift":
        new["core_config"]["model"]["temperature"] = 1
        new["disclosed_control_changes"] = {
            "model": {
                "before": old["core_config"]["model"],
                "after": new["core_config"]["model"],
            }
        }
    elif tamper == "runtime-drift":
        new["runtime_conditions"]["timeouts"]["branch"] = 181
    elif tamper == "missing-runtime-field":
        old["runtime_conditions"].pop("clock")
        new["runtime_conditions"].pop("clock")
        policy["original_binding_sha256"] = canonical_hash(
            {k: v for k, v in old.items() if k != "root"}
        )
    elif tamper == "empty-native":
        old["native_measurement_files"] = new["native_measurement_files"] = {}
        policy["original_binding_sha256"] = canonical_hash(
            {k: v for k, v in old.items() if k != "root"}
        )
    elif tamper == "runtime-type-drift":
        new["runtime_conditions"]["plan_ttl_seconds"] = 1800.0
    elif tamper == "config-type-drift":
        new["core_config"]["model"]["temperature"] = False
    else:
        new["identity"].pop("controller")
    repin(example)
    with pytest.raises(PermissionError):
        m.validate_recovery_equivalence(old, new, pin)


def test_qualified_ast_nodes_keep_class_shell_and_sibling_business_nodes():
    m = module()
    nodes = m.describe_ast_nodes(
        "class Authority:\n    def claim(self):\n        return 1\n    def business(self):\n        return 1800\n"
    )
    assert "class:Authority/function:claim" in nodes
    assert "class:Authority/function:business" in nodes
    assert "class:Authority" in nodes


def test_duplicate_qualified_selectors_fail_closed():
    with pytest.raises(PermissionError):
        module().describe_ast_nodes(
            "def authority():\n    return 1\ndef authority():\n    return 2\n"
        )


def reframe(example, monkeypatch, before, after, selectors):
    m, old, new, policy, _, name = example
    (Path(old["root"]) / name).write_bytes(before.encode())
    (Path(new["root"]) / name).write_bytes(after.encode())
    old["measurement_files"][name] = digest(before.encode())
    new["measurement_files"][name] = digest(after.encode())
    receipt = write_json(
        Path(old["root"]) / "source_receipt.json", {"files": old["measurement_files"]}
    )
    monkeypatch.setattr(m, "ORIGINAL_SOURCE_RECEIPT_SHA256", receipt["sha256"])
    old["source_receipt_pin"] = receipt
    old_nodes, new_nodes = m.describe_ast_nodes(before), m.describe_ast_nodes(after)
    policy["changes"][name] = {
        "before_sha256": old["measurement_files"][name],
        "after_sha256": new["measurement_files"][name],
        "nodes": {
            selector: {
                "before_sha256": old_nodes.get(selector),
                "after_sha256": new_nodes.get(selector),
            }
            for selector in selectors
        },
    }
    policy["original_binding_sha256"] = canonical_hash(
        {k: v for k, v in old.items() if k != "root"}
    )
    repin(example)


def test_reviewed_member_import_and_new_class_are_bound_independently(
    example, monkeypatch
):
    m, old, new, _, pin, _ = example
    before = "from typing import Literal\n\nclass Journal:\n    def claim(self):\n        return 'v1'\n    def business(self):\n        return 1800\n"
    after = (
        before.replace("import Literal", "import Literal, Annotated").replace(
            "return 'v1'", "return 'v2'"
        )
        + "\nclass LimitedAuthority:\n    policy = 'exact'\n"
    )
    reframe(
        example,
        monkeypatch,
        before,
        after,
        ["from:typing", "class:Journal/function:claim", "class:LimitedAuthority"],
    )
    assert m.validate_recovery_equivalence(old, new, pin)["timing_credit"] is False


@pytest.mark.parametrize(
    "tamper", ["sibling", "class-shell", "whole-class", "relocation", "removed-node"]
)
def test_class_member_policy_cannot_exclude_business_or_class_shell(
    example, monkeypatch, tamper
):
    m, old, new, _, pin, _ = example
    before = "class Journal:\n    def claim(self):\n        return 'v1'\n    def business(self):\n        return 1800\n"
    after = before.replace("return 'v1'", "return 'v2'")
    selectors = ["class:Journal/function:claim"]
    if tamper == "sibling":
        after = after.replace("return 1800", "return 1799")
    elif tamper == "class-shell":
        after = after.replace("class Journal:", "class Journal(object):")
    elif tamper == "whole-class":
        selectors = ["class:Journal"]
    elif tamper == "relocation":
        after = "class Journal:\n    def business(self):\n        return 1800\n    def claim(self):\n        return 'v2'\n"
    else:
        after = "class Journal:\n    def business(self):\n        return 1800\n"
    reframe(example, monkeypatch, before, after, selectors)
    with pytest.raises(PermissionError):
        m.validate_recovery_equivalence(old, new, pin)


def test_missing_physical_worker_file_cannot_be_replaced_by_declared_hash(example):
    m, old, new, _, pin, _ = example
    (Path(new["root"]) / "worker/file_0.py").unlink()
    with pytest.raises(PermissionError):
        m.validate_recovery_equivalence(old, new, pin)


def test_original_manifest_cannot_be_resigned_with_a_reduced_file_map(example):
    m, old, new, _, pin, _ = example
    old["measurement_files"].pop("worker/file_0.py")
    write_json(
        Path(old["root"]) / "source_receipt.json", {"files": old["measurement_files"]}
    )
    with pytest.raises(PermissionError):
        m.validate_recovery_equivalence(old, new, pin)


def test_exact_file_raw_hash_still_required_when_ast_is_unchanged(example):
    m, old, new, _, pin, name = example
    path = Path(new["root"]) / name
    path.write_bytes(path.read_bytes() + b"\n# unreviewed bytes\n")
    with pytest.raises(PermissionError):
        m.validate_recovery_equivalence(old, new, pin)


def test_transform_fingerprint_excludes_declared_future_commit_and_identity(example):
    m, old, new, policy, pin, _ = example
    original_fingerprint = m.review_policy_fingerprint(policy)
    new["identity"]["controller"]["source_commit"] = "e" * 40
    repin(example, review=False)
    assert m.review_policy_fingerprint(policy) == original_fingerprint
    proof = m.validate_recovery_equivalence(old, new, pin)
    assert proof["authorization"] is False and proof["timing_credit"] is False
    assert proof["candidate_identity"] == new["identity"]
    assert proof["transformation_sha256"] == original_fingerprint


@pytest.mark.parametrize(
    "change", ["worker-map", "native-map", "ast-node", "raw-node-file"]
)
def test_changed_transformation_cannot_reuse_a_review_registration(example, change):
    m, old, new, policy, pin, name = example
    original_fingerprint = m.review_policy_fingerprint(policy)
    if change == "worker-map":
        policy["candidate_measurement_files"]["worker/file_0.py"] = "f" * 64
    elif change == "native-map":
        policy["candidate_native_measurement_files"]["evals/e_timing.py"] = "f" * 64
    elif change == "ast-node":
        policy["changes"][name]["nodes"]["function:authority"]["after_sha256"] = (
            "f" * 64
        )
    else:
        policy["changes"][name]["after_sha256"] = "f" * 64
    assert m.review_policy_fingerprint(policy) != original_fingerprint
    pin.update(write_json(Path(pin["path"]), policy))
    with pytest.raises(PermissionError):
        m.validate_recovery_equivalence(old, new, pin)


def test_original_receipt_may_be_independently_pinned_outside_code_root(example):
    m, old, new, policy, pin, _ = example
    previous = Path(old["source_receipt_pin"]["path"])
    separate = previous.parent.parent / "independent-original-receipt.json"
    separate.write_bytes(previous.read_bytes())
    previous.unlink()
    old["source_receipt_pin"]["path"] = str(separate)
    policy["original_binding_sha256"] = canonical_hash(
        {k: v for k, v in old.items() if k != "root"}
    )
    repin(example, review=False)
    assert m.validate_recovery_equivalence(old, new, pin)["timing_credit"] is False


def control_change(before, after, node_pins):
    return {
        "before_sha256": digest(before.encode()),
        "after_sha256": digest(after.encode()),
        "nodes": {
            selector: {
                "before_sha256": ast_hash(old) if old else None,
                "after_sha256": ast_hash(new),
            }
            for selector, (old, new) in node_pins.items()
        },
    }


@pytest.mark.parametrize(
    "statement",
    [
        "_ACTIVE_CONTROLLER_LOCKS = {}\n",
        "_ACTIVE_CONTROLLER_LOCKS: dict[int, object] = {}\n",
    ],
)
def test_new_exact_empty_controller_lock_assignment_can_be_reviewed(statement):
    m = module()
    before = "LIMITS = {'logical': 6}\n"
    after = before + statement
    selector = "assign:_ACTIVE_CONTROLLER_LOCKS"
    assert selector in m.describe_ast_nodes(after)
    m._validate_control_file(
        "evals/adapters/source_epochs.py",
        before.encode(),
        after.encode(),
        control_change(before, after, {selector: (None, statement)}),
    )


@pytest.mark.parametrize(
    "source",
    [
        "A = B = {}\n",
        "A, B = {}, {}\n",
        "A = {}\nA = {}\n",
        "A = {}\nA: dict = {}\n",
        "A = {}\ndef A():\n    pass\n",
    ],
)
def test_assignment_selectors_reject_multiple_targets_and_duplicate_definitions(source):
    with pytest.raises(PermissionError):
        module().describe_ast_nodes(source)


@pytest.mark.parametrize(
    "statement",
    [
        "LIMITS = {'logical': 7}\n",
        "_ACTIVE_CONTROLLER_LOCKS = {'bypass': True}\n",
        "_ACTIVE_CONTROLLER_LOCKS = dict()\n",
    ],
)
def test_assignment_support_cannot_open_existing_business_constants(statement):
    before = "LIMITS = {'logical': 6}\n"
    selector = (
        "assign:LIMITS"
        if statement.startswith("LIMITS")
        else "assign:_ACTIVE_CONTROLLER_LOCKS"
    )
    after = statement if selector == "assign:LIMITS" else before + statement
    with pytest.raises(PermissionError):
        module()._validate_control_file(
            "evals/adapters/source_epochs.py",
            before.encode(),
            after.encode(),
            control_change(
                before,
                after,
                {
                    selector: (
                        before if selector == "assign:LIMITS" else None,
                        statement,
                    )
                },
            ),
        )


def test_verification_consumer_can_review_only_exact_schema_route():
    m = module()
    old_function = "def observed_timing_max(receipt, identity):\n    return 'v1'\n"
    new_function = (
        "def observed_timing_max(receipt, identity):\n    return 'v1-v2-route'\n"
    )
    immutable = "\ndef _immutable(path, value):\n    return value\n"
    before, after = old_function + immutable, new_function + immutable
    change = control_change(
        before, after, {"function:observed_timing_max": (old_function, new_function)}
    )
    m._validate_control_file(
        "evals/verification_v2.py", before.encode(), after.encode(), change
    )


def test_f8_admission_consumer_method_requires_its_exact_reviewed_node():
    m = module()
    before = (
        "class VerificationCampaign:\n"
        "    async def run_case(self, receipt):\n"
        "        return observed_six_branch_max(receipt, self.identity)\n"
    )
    after = before.replace("observed_six_branch_max", "observed_timing_max")
    selector = "class:VerificationCampaign/function:run_case"
    change = {
        "before_sha256": sha256(before.encode()).hexdigest(),
        "after_sha256": sha256(after.encode()).hexdigest(),
        "nodes": {
            selector: {
                "before_sha256": m.describe_ast_nodes(before)[selector],
                "after_sha256": m.describe_ast_nodes(after)[selector],
            }
        },
    }
    m._validate_control_file(
        "evals/verification_v2.py", before.encode(), after.encode(), change
    )


def test_ambiguous_import_selector_is_not_excludable_and_remains_in_skeleton():
    m = module()
    imports = "from package import first\nfrom package import second\n"
    old_function = "def observed_timing_max(receipt, identity):\n    return 'v1'\n"
    new_function = old_function.replace("'v1'", "'v2'")
    before, after = imports + old_function, imports + new_function
    assert "from:package" not in m.describe_ast_nodes(before)
    change = control_change(
        before, after, {"function:observed_timing_max": (old_function, new_function)}
    )
    m._validate_control_file(
        "evals/verification_v2.py", before.encode(), after.encode(), change
    )
    tampered = after.replace("import first", "import bypass")
    change["after_sha256"] = digest(tampered.encode())
    with pytest.raises(PermissionError):
        m._validate_control_file(
            "evals/verification_v2.py", before.encode(), tampered.encode(), change
        )


@pytest.mark.parametrize("also_pin", [False, True])
def test_verification_consumer_review_cannot_open_immutable_or_six_branch_nodes(
    also_pin,
):
    old_route = "def observed_timing_max(receipt, identity):\n    return 'v1'\n"
    new_route = old_route.replace("'v1'", "'v1-v2-route'")
    old_immutable = "def _immutable(path, value):\n    return value\n"
    new_immutable = old_immutable.replace("return value", "return None")
    before, after = old_route + old_immutable, new_route + new_immutable
    pins = {"function:observed_timing_max": (old_route, new_route)}
    if also_pin:
        pins["function:_immutable"] = (old_immutable, new_immutable)
    with pytest.raises(PermissionError):
        module()._validate_control_file(
            "evals/verification_v2.py",
            before.encode(),
            after.encode(),
            control_change(before, after, pins),
        )


@pytest.mark.parametrize(
    "file",
    ["evals/adapters/additional_analysis.py", "evals/adapters/planning_recovery.py"],
)
def test_registration_validator_delegation_has_only_exact_review_units(file):
    m = module()
    protected = (
        "def verify_ledger(manifest, blobs):\n    return 'strict-original-ledger'\n"
    )
    if file.endswith("additional_analysis.py"):
        old_function = "def _validate_recovery_validation_sources(manifest, blobs):\n    return 'original-validator-pins'\n"
        new_function = old_function.replace(
            "'original-validator-pins'", "'exact-reviewed-delegation'"
        )
        before, after = protected + old_function, protected + new_function
        pins = {
            "function:_validate_recovery_validation_sources": (
                old_function,
                new_function,
            )
        }
    else:
        registry = "def _reviewed_registration_validator_delegations():\n    return frozenset()\n"
        validator = "def validate_registration_validator_delegation(manifest, blobs):\n    return False\n"
        before, after = protected, protected + registry + validator
        pins = {
            "function:_reviewed_registration_validator_delegations": (None, registry),
            "function:validate_registration_validator_delegation": (None, validator),
        }
    m._validate_control_file(
        file, before.encode(), after.encode(), control_change(before, after, pins)
    )


@pytest.mark.parametrize(
    "file",
    ["evals/adapters/additional_analysis.py", "evals/adapters/planning_recovery.py"],
)
@pytest.mark.parametrize("also_pin", [False, True])
def test_registration_delegation_cannot_exclude_ledger_or_other_business(
    file, also_pin
):
    protected = (
        "def verify_ledger(manifest, blobs):\n    return 'strict-original-ledger'\n"
    )
    tampered = protected.replace("'strict-original-ledger'", "'bypass'")
    name = (
        "_validate_recovery_validation_sources"
        if file.endswith("additional_analysis.py")
        else "validate_registration_validator_delegation"
    )
    old_function = f"def {name}(manifest, blobs):\n    return False\n"
    new_function = old_function.replace("False", "True")
    before, after = protected + old_function, tampered + new_function
    pins = {f"function:{name}": (old_function, new_function)}
    if also_pin:
        pins["function:verify_ledger"] = (protected, tampered)
    with pytest.raises(PermissionError):
        module()._validate_control_file(
            file, before.encode(), after.encode(), control_change(before, after, pins)
        )
