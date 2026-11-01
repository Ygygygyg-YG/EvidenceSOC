"""Read-only recovery equivalence; never grants authority or timing credit.

Transformations are admitted by an independently reviewed semantic digest in
this module, not by a caller's whitelist or a policy's own review claim.
Only independently reviewed exact transformations enter the production registry.
No candidate code is imported, compiled or executed by this verifier.
"""

from __future__ import annotations

import ast
import json
import re
from copy import deepcopy
from hashlib import sha256
from pathlib import PurePosixPath

from evals.contracts import canonical_hash
from evals.e_timing import BOOTSTRAP, ORDER
from evals.timing_pool import _directory, _plain, validate_condition_equivalence

ORIGINAL_SOURCE_RECEIPT_SHA256 = (
    "035aaecf7c610dbec774288ae3e409bc3fd7fc8a8f100a70727c3e3165dbcbb4"
)
# Add a transformation fingerprint only after independent final review of its
# exact source maps and implementations. Identity/commit metadata is declared,
# and must be verified by the external native evidence and scope validators.
# Excluding that future metadata avoids a policy/commit registration cycle.
REVIEWED_RECOVERY_POLICIES: frozenset[str] = frozenset(
    {"e53f7d7dbfcf2aa0121de613d7e3e3e63e0548c1cc798734d619fad38b1c281a"}
)

TRANSFORMATION_FIELDS = frozenset(
    {
        "schema_version",
        "original_source_receipt_sha256",
        "original_measurement_files",
        "candidate_measurement_files",
        "original_native_measurement_files",
        "candidate_native_measurement_files",
        "changes",
    }
)
REQUIRED_NATIVE_MEASUREMENT_FILES = frozenset(
    {
        "evals/e_timing.py",
        "evals/e_planning.py",
        "evals/verification.py",
        "evals/verification_v2.py",
        "scripts/task13_e_trial.py",
    }
)

CONTROL_FILES = frozenset(
    {
        "evals/adapters/e_planning_journal.py",
        "evals/adapters/source_epochs.py",
        "evals/adapters/model_identities.py",
        "scripts/task13_e_trial.py",
        "evals/verification_v2.py",
        "evals/adapters/additional_analysis.py",
        "evals/adapters/planning_recovery.py",
    }
)
CONTROL_NODE_LIMITS = {
    "evals/verification_v2.py": frozenset(
        {
            "function:observed_timing_max",
            "class:VerificationCampaign/function:run_case",
        }
    ),
    "evals/adapters/additional_analysis.py": frozenset(
        {"function:_validate_recovery_validation_sources"}
    ),
    "evals/adapters/planning_recovery.py": frozenset(
        {
            "function:_reviewed_registration_validator_delegations",
            "function:validate_registration_validator_delegation",
        }
    ),
}
EXECUTION_FIELDS = frozenset(
    {
        "root",
        "measurement_files",
        "native_measurement_files",
        "identity",
        "core_config",
        "disclosed_control_changes",
        "candidate_conditions",
        "measurement_constants",
        "runtime_conditions",
    }
)
RUNTIME_FIELDS = frozenset(
    {"budget", "plan_ttl_seconds", "timeouts", "seed", "clock", "branch_order"}
)
CONDITION_FIELDS = frozenset(
    {
        "received_model",
        "image_id",
        "dependencies_lock_sha256",
        "dependencies_tree_sha256",
        "knowledge_sha256",
    }
)


def _sha(raw):
    return sha256(raw).hexdigest()


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PermissionError("invalid recovery digest")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PermissionError("duplicate recovery JSON key")
        result[key] = value
    return result


def _json(raw):
    def invalid_constant(value):
        raise PermissionError("nonfinite recovery JSON")

    return json.loads(
        raw, object_pairs_hook=_unique_object, parse_constant=invalid_constant
    )


def _relative(value):
    if not isinstance(value, str) or "\\" in value or ":" in value:
        raise PermissionError("normalized relative source path required")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != value
        or not path.parts
    ):
        raise PermissionError("normalized relative source path required")
    return value


def _inventory(value):
    if not isinstance(value, dict) or not value:
        raise PermissionError("complete nonempty source inventory required")
    for path, digest in value.items():
        _relative(path)
        _digest(digest)
    return value


def _read_files(root, files):
    result = {}
    for relative, digest in files.items():
        path = _plain(root / _relative(relative))
        path.relative_to(root)
        raw = path.read_bytes()
        if _sha(raw) != digest:
            raise PermissionError("recovery inventory raw bytes differ")
        result[relative] = raw
    return result


def _selector(node):
    if isinstance(node, ast.ClassDef):
        return "class:" + node.name
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return "function:" + node.name
    if isinstance(node, ast.ImportFrom):
        return "from:" + "." * node.level + (node.module or "")
    if isinstance(node, ast.Import):
        return "import:" + ",".join(alias.name for alias in node.names)
    if isinstance(node, ast.Assign):
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            raise PermissionError(
                "recovery assignment selector requires one simple target"
            )
        return "assign:" + node.targets[0].id
    if isinstance(node, ast.AnnAssign):
        if not isinstance(node.target, ast.Name):
            raise PermissionError(
                "recovery annotation selector requires one simple target"
            )
        return "assign:" + node.target.id
    return None


def _index(tree):
    result = {}
    ambiguous_imports = set()

    def visit(body, prefix=""):
        definitions = set()
        for node in body:
            selector = _selector(node)
            if selector is None:
                continue
            qualified = prefix + selector
            if isinstance(
                node,
                (
                    ast.ClassDef,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.Assign,
                    ast.AnnAssign,
                ),
            ):
                name = selector.split(":", 1)[1]
                if name in definitions:
                    raise PermissionError("duplicate recovery definition or assignment")
                definitions.add(name)
            if qualified in ambiguous_imports:
                continue
            if qualified in result:
                if isinstance(node, (ast.Import, ast.ImportFrom)) and isinstance(
                    result[qualified], (ast.Import, ast.ImportFrom)
                ):
                    # Existing split imports are legal Python. They are kept
                    # verbatim in the skeleton and cannot be selected as a hole.
                    ambiguous_imports.add(qualified)
                    del result[qualified]
                    continue
                raise PermissionError("duplicate qualified recovery AST selector")
            result[qualified] = node
            # Class members are independently pinned. A function body remains
            # one review unit; nested business statements cannot be excluded.
            if isinstance(node, ast.ClassDef):
                visit(node.body, qualified + "/")

    visit(tree.body)
    return result


def _node_sha(node):
    return _sha(ast.dump(node, include_attributes=False).encode("utf-8"))


def describe_ast_nodes(source):
    """Return qualified semantic node hashes for a draft review; no admission."""
    try:
        tree = ast.parse(source)
        return {name: _node_sha(node) for name, node in _index(tree).items()}
    except PermissionError:
        raise
    except (ValueError, TypeError, SyntaxError, UnicodeError) as error:
        raise PermissionError("invalid recovery Python AST") from error


def _skeleton(tree, selected, *, added):
    def rewrite(body, prefix=""):
        result = []
        for node in body:
            selector = _selector(node)
            qualified = prefix + selector if selector is not None else None
            if qualified in selected:
                if qualified not in added:
                    result.append(
                        ast.Expr(value=ast.Constant(value="reviewed:" + qualified))
                    )
                continue
            if isinstance(node, ast.ClassDef):
                node.body = rewrite(node.body, qualified + "/")
            result.append(node)
        return result

    result = deepcopy(tree)
    result.body = rewrite(result.body)
    return ast.dump(result, include_attributes=False)


def _validate_control_file(relative, before, after, change):
    if relative not in CONTROL_FILES or set(change) != {
        "before_sha256",
        "after_sha256",
        "nodes",
    }:
        raise PermissionError("file is not a reviewed recovery control change")
    if change["before_sha256"] != _sha(before) or change["after_sha256"] != _sha(after):
        raise PermissionError("reviewed whole-file recovery pins differ")
    old_tree, new_tree = ast.parse(before), ast.parse(after)
    old, new = _index(old_tree), _index(new_tree)
    nodes = change["nodes"]
    if not isinstance(nodes, dict) or not nodes:
        raise PermissionError("exact recovery node changes required")
    if relative in CONTROL_NODE_LIMITS and set(nodes) - CONTROL_NODE_LIMITS[relative]:
        raise PermissionError(
            "control file may change only its specifically bounded review nodes"
        )
    added = set()
    for qualified, pin in nodes.items():
        if set(pin) != {"before_sha256", "after_sha256"}:
            raise PermissionError("invalid recovery node pin")
        if any(
            qualified.startswith(other + "/") for other in nodes if other != qualified
        ):
            raise PermissionError("overlapping recovery AST exclusions forbidden")
        previous, current = old.get(qualified), new.get(qualified)
        if isinstance(current, (ast.Assign, ast.AnnAssign)) and (
            relative != "evals/adapters/source_epochs.py"
            or qualified != "assign:_ACTIVE_CONTROLLER_LOCKS"
            or previous is not None
            or not isinstance(current.value, ast.Dict)
            or current.value.keys
        ):
            raise PermissionError(
                "only the new exact empty controller-lock registry may be assigned"
            )
        if current is None or (
            previous is not None and isinstance(previous, ast.ClassDef)
        ):
            raise PermissionError(
                "existing classes or removed nodes cannot be excluded"
            )
        if previous is None:
            if pin["before_sha256"] is not None:
                raise PermissionError("new recovery node has a fabricated predecessor")
            added.add(qualified)
        elif pin["before_sha256"] != _node_sha(previous):
            raise PermissionError("original recovery node pin differs")
        if pin["after_sha256"] != _node_sha(current):
            raise PermissionError("candidate recovery node pin differs")
        if previous is not None and _node_sha(previous) == _node_sha(current):
            raise PermissionError("unchanged nodes cannot widen a recovery policy")
    if _skeleton(old_tree, set(nodes), added=added) != _skeleton(
        new_tree, set(nodes), added=added
    ):
        raise PermissionError(
            "business, imports, constants or class shell changed outside reviewed nodes"
        )


def _execution(value, *, original=False):
    required = EXECUTION_FIELDS | ({"source_receipt_pin"} if original else set())
    if not isinstance(value, dict) or set(value) != required:
        raise PermissionError("complete exact recovery execution fields required")
    root = _directory(value["root"])
    files = _inventory(value["measurement_files"])
    native = _inventory(value["native_measurement_files"])
    if len(files) != 117 or not REQUIRED_NATIVE_MEASUREMENT_FILES <= native.keys():
        raise PermissionError(
            "117 worker files plus original native measurement paths required"
        )
    if any(files[k] != native[k] for k in files.keys() & native.keys()):
        raise PermissionError("worker and native overlapping source pins differ")
    identity = value["identity"]
    if set(identity) != {"source", "model", "controller"} or any(
        not isinstance(v, dict) or not v for v in identity.values()
    ):
        raise PermissionError(
            "original source, model and controller identities required"
        )
    conditions = value["candidate_conditions"]
    if set(conditions) != CONDITION_FIELDS or any(not v for v in conditions.values()):
        raise PermissionError(
            "complete declared model and environment conditions required"
        )
    if set(conditions["received_model"]) != {"response_model", "fingerprint"} or any(
        not v for v in conditions["received_model"].values()
    ):
        raise PermissionError("declared received model identity missing")
    runtime = value["runtime_conditions"]
    if set(runtime) != RUNTIME_FIELDS or not runtime["budget"] or not runtime["clock"]:
        raise PermissionError("complete runtime conditions required")
    expected_order = [list(x) for x in ORDER]
    if (
        type(runtime["plan_ttl_seconds"]) is not int
        or runtime["plan_ttl_seconds"] != 1800
        or canonical_hash(runtime["branch_order"]) != canonical_hash(expected_order)
    ):
        raise PermissionError("original approval TTL and six-branch order required")
    if canonical_hash(value["measurement_constants"]) != canonical_hash(
        {
            "bootstrap": BOOTSTRAP,
            "order": expected_order,
        }
    ):
        raise PermissionError("original bootstrap and six-branch constants required")
    return root, files, native


def review_policy_fingerprint(policy):
    """Fingerprint only the reviewed implementation transformation.

    Future source/model/controller IDs, commits, full bindings, receipt paths,
    and review records do not participate. This is never an identity or scope
    authorization check. The external scope must pin the final policy raw SHA.
    """
    try:
        return canonical_hash({key: policy[key] for key in TRANSFORMATION_FIELDS})
    except (KeyError, TypeError, ValueError) as error:
        raise PermissionError("incomplete recovery transformation") from error


def _policy(pin):
    if not isinstance(pin, dict) or set(pin) != {"path", "sha256"}:
        raise PermissionError("independent raw policy reference required")
    expected = _digest(pin["sha256"])
    raw = _plain(pin["path"]).read_bytes()
    if _sha(raw) != expected:
        raise PermissionError("reviewed recovery policy raw bytes differ")
    policy = _json(raw)
    if (
        set(policy)
        != TRANSFORMATION_FIELDS
        | {
            "review",
            "original_binding_sha256",
            "candidate_binding_sha256",
        }
        or policy["schema_version"] != "task13-recovery-equivalence-policy-v1"
    ):
        raise PermissionError("invalid reviewed recovery policy")
    if policy["original_source_receipt_sha256"] != ORIGINAL_SOURCE_RECEIPT_SHA256:
        raise PermissionError("reviewed original worker receipt anchor differs")
    if review_policy_fingerprint(policy) not in REVIEWED_RECOVERY_POLICIES:
        raise PermissionError(
            "no independently reviewed recovery transformation registered"
        )
    review = policy["review"]
    if (
        set(review) != {"status", "review_record_sha256"}
        or review["status"] != "reviewed"
        or _digest(review["review_record_sha256"]) == "0" * 64
    ):
        raise PermissionError("final independent recovery review missing")
    return policy


def validate_recovery_equivalence(original_execution, candidate_execution, policy_pin):
    """Check reviewed source/control equivalence without creating any authority.

    ``candidate_conditions`` are declarations, including on a future candidate;
    native observation/ledger/actual-model checks remain separately mandatory.
    The original and candidate identities are preserved as separate objects.
    ``runtime_conditions`` requires budget, plan_ttl_seconds, timeouts, seed,
    clock and branch_order; each full value must be equal across executions.
    """
    try:
        policy = _policy(policy_pin)
        old_root, old_files, old_native = _execution(original_execution, original=True)
        new_root, new_files, new_native = _execution(candidate_execution)
        for label, execution in (
            ("original", original_execution),
            ("candidate", candidate_execution),
        ):
            binding = {k: v for k, v in execution.items() if k != "root"}
            if canonical_hash(binding) != policy[label + "_binding_sha256"]:
                raise PermissionError("reviewed recovery execution binding differs")
        for key, actual in (
            ("original_measurement_files", old_files),
            ("candidate_measurement_files", new_files),
            ("original_native_measurement_files", old_native),
            ("candidate_native_measurement_files", new_native),
        ):
            if canonical_hash(policy[key]) != canonical_hash(actual):
                raise PermissionError("reviewed transformation inventory differs")
        original_receipt = original_execution["source_receipt_pin"]
        if (
            set(original_receipt) != {"path", "sha256"}
            or original_receipt["sha256"] != ORIGINAL_SOURCE_RECEIPT_SHA256
        ):
            raise PermissionError(
                "independently pinned original worker receipt required"
            )
        receipt_raw = _plain(original_receipt["path"]).read_bytes()
        if (
            _sha(receipt_raw) != ORIGINAL_SOURCE_RECEIPT_SHA256
            or _json(receipt_raw)["files"] != old_files
        ):
            raise PermissionError("original complete worker manifest anchor differs")
        if set(old_files) != set(new_files) or set(old_native) != set(new_native):
            raise PermissionError("complete original source inventories required")
        before = _read_files(old_root, {**old_files, **old_native})
        after = _read_files(new_root, {**new_files, **new_native})
        changed = {path for path in before if before[path] != after[path]}
        if not isinstance(policy["changes"], dict) or set(policy["changes"]) != changed:
            raise PermissionError("undeclared or stale recovery control differences")
        for path in sorted(changed):
            _validate_control_file(
                path, before[path], after[path], policy["changes"][path]
            )
        validate_condition_equivalence(
            original_execution["core_config"],
            candidate_execution["core_config"],
            candidate_execution["disclosed_control_changes"],
        )
        # Python equality conflates bool/int and int/float. Exact JSON hashes
        # keep model parameters and every undisclosed value type unchanged.
        original_config, candidate_config = (
            original_execution["core_config"],
            candidate_execution["core_config"],
        )
        strict_changes = {
            key: {
                "before": original_config.get(key),
                "after": candidate_config.get(key),
            }
            for key in original_config.keys() | candidate_config.keys()
            if key not in original_config
            or key not in candidate_config
            or canonical_hash(original_config[key])
            != canonical_hash(candidate_config[key])
        }
        if canonical_hash(strict_changes) != canonical_hash(
            candidate_execution["disclosed_control_changes"]
        ):
            raise PermissionError("control changes must preserve exact JSON types")
        if original_execution["disclosed_control_changes"]:
            raise PermissionError(
                "original execution cannot be relabelled as a migration"
            )
        for key in (
            "candidate_conditions",
            "measurement_constants",
            "runtime_conditions",
        ):
            if canonical_hash(original_execution[key]) != canonical_hash(
                candidate_execution[key]
            ):
                raise PermissionError(
                    "model, environment or measurement runtime conditions differ"
                )
        return deepcopy(
            {
                "schema_version": "task13-recovery-equivalence-proof-v1",
                "scope": "source-and-declared-conditions-only",
                "timing_credit": False,
                "authorization": False,
                "policy_sha256": policy_pin["sha256"],
                "transformation_sha256": review_policy_fingerprint(policy),
                "original_identity": original_execution["identity"],
                "candidate_identity": candidate_execution["identity"],
                "original_measurement_files": old_files,
                "candidate_measurement_files": new_files,
                "native_measurement_files": old_native,
                "candidate_native_measurement_files": new_native,
                "changed_files": sorted(changed),
                "reviewed_nodes": {p: c["nodes"] for p, c in policy["changes"].items()},
                "declared_candidate_conditions": candidate_execution[
                    "candidate_conditions"
                ],
                "original_binding_sha256": policy["original_binding_sha256"],
                "candidate_binding_sha256": policy["candidate_binding_sha256"],
            }
        )
    except PermissionError:
        raise
    except (
        KeyError,
        ValueError,
        TypeError,
        AttributeError,
        OSError,
        SyntaxError,
        UnicodeError,
    ) as error:
        raise PermissionError("invalid recovery equivalence evidence") from error
