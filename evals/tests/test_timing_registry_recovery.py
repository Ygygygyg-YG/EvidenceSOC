"""Historical analysis reuse permits only the exact timing-v2 dispatch addition."""

import ast
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from evals.adapters import additional_analysis, planning_recovery
from evals.tests.test_response_transport_recovery import metadata_inputs

LEGACY = 'registration.get("schema_version") == "task13-e-timing-registration-v1"'
SUPPORTED = (
    'registration.get("schema_version") in '
    '{"task13-e-timing-registration-v1", "task13-e-timing-registration-v2"}'
)


def source():
    return (
        Path(__file__).resolve().parents[1] / "adapters/source_epochs.py"
    ).read_bytes()


def legacy_source():
    module = ast.parse(source())
    fn = next(
        n
        for n in module.body
        if isinstance(n, ast.FunctionDef) and n.name == "_lock_controller_roots"
    )
    guards = {
        ast.dump(ast.parse(test, mode="eval").body) for test in (LEGACY, SUPPORTED)
    }
    (block,) = [
        n for n in ast.walk(fn) if isinstance(n, ast.If) and ast.dump(n.test) in guards
    ]
    block.test = ast.parse(LEGACY, mode="eval").body
    return ast.unparse(ast.fix_missing_locations(module)).encode()


def validate(raw):
    check = getattr(planning_recovery, "validate_timing_registry_equivalence", None)
    assert callable(check), "strict timing registry equivalence is missing"
    check(raw)


def test_legacy_timing_registry_is_compatible_with_exact_v2_addition():
    validate(legacy_source())
    validate(source())


@pytest.mark.parametrize(
    "before,after",
    [
        (
            "registration.get('schema_version') == 'task13-e-timing-registration-v1'",
            "registration.get('schema_version') != 'task13-e-timing-registration-v1'",
        ),
        ("state = read_timing_journal(root)", "state = {}"),
        (
            "from evals.e_timing import read_timing_journal",
            "from attacker import read_timing_journal",
        ),
        ("'completed',", "'running',"),
        ("row.get('review_pending')", "False"),
        ("def register_source_epoch(", "def different_registration("),
    ],
)
def test_unrelated_registry_or_quiescence_changes_are_rejected(before, after):
    raw = legacy_source().decode()
    assert before in raw
    with pytest.raises(ValueError):
        validate(raw.replace(before, after, 1).encode())


@pytest.mark.parametrize(
    "kind", ["missing", "duplicate", "moved", "unknown_schema", "malformed"]
)
def test_guard_must_be_unique_exact_and_in_its_original_position(kind):
    module = ast.parse(legacy_source())
    fn = next(
        n
        for n in module.body
        if isinstance(n, ast.FunctionDef) and n.name == "_lock_controller_roots"
    )
    (block,) = [
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.If)
        and ast.dump(n.test) == ast.dump(ast.parse(LEGACY, mode="eval").body)
    ]
    if kind == "missing":
        block.test = ast.Constant(True)
    elif kind == "duplicate":
        fn.body.append(deepcopy(block))
    elif kind == "moved":
        fn.body.insert(0, ast.Expr(ast.Constant("inserted behavior")))
    elif kind == "unknown_schema":
        block.test = ast.parse(
            SUPPORTED.replace("registration-v2", "registration-v3"), mode="eval"
        ).body
    else:
        with pytest.raises(ValueError):
            validate(b"invalid Python !")
        return
    with pytest.raises(ValueError):
        validate(ast.unparse(ast.fix_missing_locations(module)).encode())


def inputs():
    manifest, blobs = metadata_inputs()
    raw = legacy_source()
    blobs["original_source:evals/adapters/source_epochs.py"] = raw
    manifest.validation_source_sha256["source_epoch"] = sha256(raw).hexdigest()
    return manifest, blobs


def test_recovery_metadata_accepts_authenticated_legacy_registry_only():
    manifest, blobs = inputs()
    additional_analysis._validate_recovery_validation_sources(manifest, blobs)


@pytest.mark.parametrize(
    "kind",
    [
        "missing_blob",
        "wrong_pin",
        "tampered_blob",
        "unrelated_semantics",
        "other_dependency",
    ],
)
def test_recovery_metadata_does_not_bypass_original_pins_or_other_dependencies(kind):
    manifest, blobs = inputs()
    key = "original_source:evals/adapters/source_epochs.py"
    if kind == "missing_blob":
        del blobs[key]
    elif kind == "wrong_pin":
        manifest.validation_source_sha256["source_epoch"] = "0" * 64
    elif kind == "tampered_blob":
        blobs[key] += b"\n# unauthenticated bytes\n"
    elif kind == "unrelated_semantics":
        blobs[key] = blobs[key].replace(
            b"state = read_timing_journal(root)", b"state = {}", 1
        )
        manifest.validation_source_sha256["source_epoch"] = sha256(
            blobs[key]
        ).hexdigest()
    else:
        manifest.validation_source_sha256["budget_account"] = "0" * 64
    with pytest.raises(ValueError):
        additional_analysis._validate_recovery_validation_sources(manifest, blobs)


@pytest.mark.asyncio
async def test_normal_replay_keeps_whole_registry_hash_strict(tmp_path, monkeypatch):
    from evals.tests.test_additional_analysis import additional_source, export, verify

    original = await additional_source(tmp_path / "run", monkeypatch)
    package = tmp_path / "package"
    exported = export(original, package)
    hashes = additional_analysis._validation_source_hashes()
    monkeypatch.setattr(
        additional_analysis,
        "_validation_source_hashes",
        lambda: {**hashes, "source_epoch": "0" * 64},
    )
    with pytest.raises(ValueError, match="additional replay validator source drift"):
        verify(original, package, exported["manifest_sha256"])
