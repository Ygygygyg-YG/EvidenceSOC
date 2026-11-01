"""Exact reviewed registration-control delegation never grants execution authority."""

from hashlib import sha256
from pathlib import Path

import pytest

from evals.adapters import additional_analysis, planning_recovery
from evals.contracts import canonical_hash
from evals.tests.test_response_transport_recovery import metadata_inputs

BASELINE = (
    "7c52c2e84095082a915d1735f728f25dabe9496a7f579bf075cfef53bd108390",
    "f83a791001de4fcefe3cf278b66ef535bfe0f4f7445a1d638bf54fd89e63bcc1",
)


def inputs():
    old, blobs = metadata_inputs()
    for name in ("source_epochs", "model_identities"):
        blobs[f"original_source:evals/adapters/{name}.py"] = (
            f"# synthetic original {name}; never executed\n".encode()
        )
    hashes = dict(old.validation_source_sha256)
    hashes["source_epoch"] = sha256(
        blobs["original_source:evals/adapters/source_epochs.py"]
    ).hexdigest()
    hashes["model_identity"] = sha256(
        blobs["original_source:evals/adapters/model_identities.py"]
    ).hexdigest()
    manifest = additional_analysis.AdditionalAnalysisManifest(
        schema_version="task13-additional-analysis-package-v1",
        source_kind="additional-development-v1",
        order_index=0,
        source_row_id="synthetic-row",
        case_id="synthetic-case",
        registration_sha256="1" * 64,
        request_sha256="2" * 64,
        successful_physical_request_id="synthetic-physical-request",
        validation_source_sha256=hashes,
        package_verifier_sha256=old.package_verifier_sha256,
        artifacts={},
    )
    return manifest, blobs


def record(manifest, blobs):
    root = Path(planning_recovery.__file__).resolve().parent
    return (
        canonical_hash(manifest),
        sha256(blobs["original_source:evals/adapters/source_epochs.py"]).hexdigest(),
        sha256(blobs["original_source:evals/adapters/model_identities.py"]).hexdigest(),
        *BASELINE,
        sha256((root / "source_epochs.py").read_bytes()).hexdigest(),
        sha256((root / "model_identities.py").read_bytes()).hexdigest(),
    )


def reviewed(monkeypatch, item):
    monkeypatch.setattr(
        planning_recovery,
        "_reviewed_registration_validator_delegations",
        lambda: frozenset({item}),
        raising=False,
    )


def test_unreviewed_synthetic_chain_is_denied_by_production_registry():
    manifest, blobs = inputs()
    registry = getattr(
        planning_recovery, "_reviewed_registration_validator_delegations", None
    )
    assert callable(registry), "exact reviewed delegation registry is missing"
    assert isinstance(registry(), frozenset)
    assert record(manifest, blobs) not in registry()
    with pytest.raises(ValueError):
        additional_analysis._validate_recovery_validation_sources(manifest, blobs)


def test_exact_reviewed_tuple_delegates_only_registration_metadata(monkeypatch):
    manifest, blobs = inputs()
    reviewed(monkeypatch, record(manifest, blobs))
    additional_analysis._validate_recovery_validation_sources(manifest, blobs)


@pytest.mark.parametrize("index", range(7))
def test_every_reviewed_pin_is_required(index, monkeypatch):
    manifest, blobs = inputs()
    wrong = list(record(manifest, blobs))
    wrong[index] = "0" * 64
    reviewed(monkeypatch, tuple(wrong))
    with pytest.raises(ValueError):
        additional_analysis._validate_recovery_validation_sources(manifest, blobs)


@pytest.mark.parametrize("name", ["source_epochs", "model_identities"])
@pytest.mark.parametrize("kind", ["missing", "tampered", "metadata_pin"])
def test_original_registration_blobs_remain_authenticated(name, kind, monkeypatch):
    manifest, blobs = inputs()
    approved = record(manifest, blobs)
    key = f"original_source:evals/adapters/{name}.py"
    if kind == "missing":
        del blobs[key]
    elif kind == "tampered":
        blobs[key] += b"# unauthenticated bytes\n"
    else:
        field = "source_epoch" if name == "source_epochs" else "model_identity"
        manifest.validation_source_sha256[field] = "0" * 64
        # Even a manifest-specific record cannot replace blob authentication.
        approved = record(manifest, blobs)
    reviewed(monkeypatch, approved)
    with pytest.raises(ValueError):
        additional_analysis._validate_recovery_validation_sources(manifest, blobs)


@pytest.mark.parametrize(
    "kind", ["other_dependency", "key_inventory", "contract", "transport", "verifier"]
)
def test_delegation_preserves_all_other_validation(kind, monkeypatch):
    manifest, blobs = inputs()
    if kind == "other_dependency":
        manifest.validation_source_sha256["budget_account"] = "0" * 64
    elif kind == "key_inventory":
        del manifest.validation_source_sha256["identity_ledger"]
    elif kind == "verifier":
        blobs["original_source:evals/adapters/additional_analysis.py"] += b"# drift\n"
    else:
        filename, field = {
            "contract": ("e_planning_contracts.py", "model_identity_contract"),
            "transport": ("model_client.py", "model_transport"),
        }[kind]
        key = f"original_source:evals/adapters/{filename}"
        original_class = (
            b"ModelIdentityBinding" if kind == "contract" else b"TrackedModel"
        )
        blobs[key] = blobs[key].replace(
            b"class " + original_class, b"class Unreviewed" + original_class, 1
        )
        manifest.validation_source_sha256[field] = sha256(blobs[key]).hexdigest()
    reviewed(monkeypatch, record(manifest, blobs))
    with pytest.raises(ValueError):
        additional_analysis._validate_recovery_validation_sources(manifest, blobs)


@pytest.mark.parametrize("filename", ["source_epochs.py", "model_identities.py"])
def test_current_registration_bytes_are_read_and_pinned(filename, monkeypatch):
    manifest, blobs = inputs()
    reviewed(monkeypatch, record(manifest, blobs))
    target = Path(planning_recovery.__file__).resolve().parent / filename
    native = Path.read_bytes

    def changed(path):
        raw = native(path)
        return raw + b"# unreviewed current bytes\n" if path == target else raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError):
        additional_analysis._validate_recovery_validation_sources(manifest, blobs)
