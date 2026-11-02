"""Regression for the production Windows path representation missed by NoGO."""

from pathlib import Path

import pytest

from scripts import task13_pool_admission as admission


def test_canaries_use_actual_runtime_staging_and_literal_host_paths(tmp_path):
    staging = tmp_path / "short"
    with admission.production_startup_canaries(
        {"temporary_root": str(staging), "output_dir": str(tmp_path / "unused")}
    ) as (forbidden, layout):
        root = Path(layout["canary_root"])
        assert root.parent == staging and root.name.startswith("task13-runtime-")
        for kind in ("scoring", "git", "other_case"):
            canary = root / kind / "canary.txt"
            assert canary.is_file()
            assert forbidden[kind][0] == str(canary.resolve())
            assert forbidden[kind][1:3] == [
                f"/app/{kind}/canary.txt",
                f"/workspace/{kind}/canary.txt",
            ]
        assert [len(forbidden[k]) for k in ("scoring", "git", "other_case")] == [
            3,
            6,
            3,
        ]
    assert not root.exists()


def test_default_staging_matches_production_controller_directory(tmp_path):
    output = tmp_path / "outputs"
    with admission.production_startup_canaries({"output_dir": str(output)}) as (
        _,
        layout,
    ):
        assert Path(layout["staging_root"]) == output / ".controller-staging"


@pytest.mark.parametrize(
    "schema",
    [
        "task13-e-timing-pool-receipt-v1",
        "task13-e-timing-pool-receipt-v2",
        "task13-e-timing-pool-receipt-v3",
    ],
)
def test_pool_receipts_route_to_exact_native_validator(monkeypatch, schema):
    from evals import timing_pool, verification_v2

    receipt, identity = {"schema_version": schema}, {"case_id": "fixed"}
    calls = []

    def checked(value, expected):
        assert value is receipt and expected is identity
        calls.append(value)
        return 384.562

    monkeypatch.setattr(timing_pool, "validate_pool_receipt", checked)
    assert verification_v2.observed_timing_max(receipt, identity) == 384.562
    assert calls == [receipt]


def test_invalid_v3_cannot_fall_back_to_legacy_six_branch_reader(monkeypatch):
    from evals import timing_pool, verification_v2

    def reject(*args):
        raise PermissionError("invalid native pool proof")

    monkeypatch.setattr(timing_pool, "validate_pool_receipt", reject)
    monkeypatch.setattr(verification_v2, "observed_six_branch_max", lambda *args: 1.0)
    with pytest.raises(PermissionError, match="invalid native pool proof"):
        verification_v2.observed_timing_max(
            {"schema_version": "task13-e-timing-pool-receipt-v3"}, {}
        )
