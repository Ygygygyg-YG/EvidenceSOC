"""Only a proved pure respond-instruction edit may reuse historical analysis."""

import ast
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.adapters import additional_analysis, planning_recovery


def transport():
    return (
        Path(__file__).resolve().parents[1] / "adapters/model_client.py"
    ).read_bytes()


def respond_block(module):
    cls = next(
        n
        for n in module.body
        if isinstance(n, ast.ClassDef) and n.name == "TrackedModel"
    )
    fn = next(
        n
        for n in cls.body
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "structured"
    )
    test = ast.dump(ast.parse('role == "respond"', mode="eval").body)
    index = next(
        i
        for i, n in enumerate(fn.body)
        if isinstance(n, ast.If) and ast.dump(n.test) == test
    )
    return fn, index, fn.body[index]


def validate(raw):
    check = getattr(planning_recovery, "validate_response_transport_equivalence", None)
    assert callable(check), "strict response-only transport equivalence is missing"
    check(raw)


def changed_block(kind):
    module = ast.parse(transport())
    fn, index, block = respond_block(module)
    if kind == "missing":
        del fn.body[index]
    elif kind == "moved":
        del fn.body[index]
        fn.body.insert(0, block)
    elif kind == "duplicate":
        fn.body.insert(index, deepcopy(block))
    elif kind == "guard":
        block.test = ast.parse('role != "respond"', mode="eval").body
    elif kind == "else":
        block.orelse = [ast.Expr(ast.Constant("other behavior"))]
    elif kind == "side_effect":
        block.body.append(ast.parse("unexpected_call()").body[0])
    elif kind == "new_call":
        block.body[0].value = ast.parse(
            '"text" + unexpected_call() + datetime.now(UTC).isoformat()', mode="eval"
        ).body
    elif kind == "fstring":
        block.body[0].value = ast.parse(
            'f"text {datetime.now(UTC).isoformat()}"', mode="eval"
        ).body
    elif kind == "clock_args":
        block.body[0].value = ast.parse(
            '"text" + datetime.now(UTC).isoformat(timespec="seconds")', mode="eval"
        ).body
    elif kind == "clock_duplicate":
        block.body[0].value = ast.parse(
            '"text" + datetime.now(UTC).isoformat() + datetime.now(UTC).isoformat()',
            mode="eval",
        ).body
    elif kind == "clock_missing":
        block.body[0].value = ast.Constant("text without the retained time call")
    elif kind == "assignment":
        block.body = ast.parse(
            'instruction = "text" + datetime.now(UTC).isoformat()'
        ).body
    elif kind == "other_target":
        block.body[0].target = ast.Name("other_instruction", ast.Store())
    else:
        raise AssertionError(kind)
    return ast.unparse(ast.fix_missing_locations(module)).encode()


def test_only_pure_response_guidance_changes_are_equivalent():
    module = ast.parse(transport())
    _, _, block = respond_block(module)
    block.body[0].value = ast.parse(
        '"Prior response guidance " + datetime.now(UTC).isoformat() + " prior tail"',
        mode="eval",
    ).body
    validate(ast.unparse(ast.fix_missing_locations(module)).encode())


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "moved",
        "duplicate",
        "guard",
        "else",
        "side_effect",
        "new_call",
        "fstring",
        "clock_args",
        "clock_duplicate",
        "clock_missing",
        "assignment",
        "other_target",
    ],
)
def test_response_block_cannot_hide_behavior_or_alter_time_call(kind):
    raw = changed_block(kind)
    assert callable(
        getattr(planning_recovery, "validate_response_transport_equivalence", None)
    ), "strict response-only transport equivalence is missing"
    with pytest.raises(ValueError):
        validate(raw)


@pytest.mark.parametrize(
    "old,new",
    [
        (b"import math", b"import math as changed_math"),
        (b'if role == "analyze" else', b'if role == "collect" else'),
        (b"schema.model_validate_json", b"schema.model_validate"),
        (b"len(encoded) + 4096", b"len(encoded) + 4097"),
        (b"self.account.bind_model(", b"self.account.settle("),
        (b"class TrackedModel:", b"class ChangedModel:"),
    ],
)
def test_analysis_parser_budget_identity_and_module_changes_are_rejected(old, new):
    assert callable(
        getattr(planning_recovery, "validate_response_transport_equivalence", None)
    ), "strict response-only transport equivalence is missing"
    raw = transport()
    assert old in raw
    with pytest.raises(ValueError):
        validate(raw.replace(old, new, 1))


def metadata_inputs():
    root = Path(__file__).resolve().parents[1] / "adapters"
    old = additional_analysis._validation_source_hashes()
    original = transport()
    blobs = {
        "original_source:evals/adapters/e_planning_contracts.py": (
            root / "e_planning_contracts.py"
        ).read_bytes(),
        "original_source:evals/adapters/additional_analysis.py": (
            root / "additional_analysis.py"
        ).read_bytes(),
        "original_source:evals/adapters/model_client.py": original,
    }
    manifest = SimpleNamespace(
        validation_source_sha256=old,
        package_verifier_sha256=sha256(
            blobs["original_source:evals/adapters/additional_analysis.py"]
        ).hexdigest(),
    )
    return manifest, blobs


def test_recovery_metadata_pins_original_transport_blob_before_equivalence():
    check = getattr(additional_analysis, "_validate_recovery_validation_sources", None)
    assert callable(check), "strict recovery source metadata validation is missing"
    manifest, blobs = metadata_inputs()
    check(manifest, blobs)
    manifest.validation_source_sha256["model_transport"] = "0" * 64
    with pytest.raises(ValueError):
        check(manifest, blobs)


def test_recovery_metadata_rejects_unrelated_science_dependency_drift():
    check = getattr(additional_analysis, "_validate_recovery_validation_sources", None)
    assert callable(check), "strict recovery source metadata validation is missing"
    manifest, blobs = metadata_inputs()
    manifest.validation_source_sha256["budget_account"] = "0" * 64
    with pytest.raises(ValueError):
        check(manifest, blobs)


@pytest.mark.asyncio
async def test_normal_replay_keeps_whole_transport_hash_strict(tmp_path, monkeypatch):
    from evals.tests.test_additional_analysis import additional_source, export, verify

    source = await additional_source(tmp_path / "run", monkeypatch)
    package = tmp_path / "package"
    exported = export(source, package)
    original = additional_analysis._validation_source_hashes()
    monkeypatch.setattr(
        additional_analysis,
        "_validation_source_hashes",
        lambda: {**original, "model_transport": "0" * 64},
    )
    with pytest.raises(ValueError, match="additional replay validator source drift"):
        verify(source, package, exported["manifest_sha256"])
