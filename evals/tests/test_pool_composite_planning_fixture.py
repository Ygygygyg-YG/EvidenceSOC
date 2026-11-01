"""Offline native model graph/ledger; never actual provider or user evidence."""

import pytest


@pytest.mark.asyncio
async def test_offline_adapter_refuses_non_copied_account(tmp_path):
    from evals.tests.pool_composite_planning_fixture import build_offline_planning

    with pytest.raises(PermissionError, match="copied SQLite"):
        await build_offline_planning(
            None,
            package_root=tmp_path,
            budget_path=tmp_path / "never-created.sqlite",
            journal_path=tmp_path / "never-claimed.sqlite",
            authority_sha256="0" * 64,
            output_root=tmp_path / "never-created",
        )
    assert not list(tmp_path.iterdir())


@pytest.mark.asyncio
async def test_current_c10_source_native_workflow_and_sql_are_offline_only(tmp_path):
    from evals.tests.pool_composite_fixture import enter_mirrored_test

    mirror = await enter_mirrored_test(
        tmp_path,
        "current_c10_source_native_workflow",
        test_file="test_pool_composite_planning_fixture.py",
    )
    if mirror is None:
        return

    from evals.contracts import canonical_hash
    from evals.e_planning import planning_requests
    from evals.tests.pool_composite_fixture import (
        isolated_native_io,
        original_account_baseline,
        register_fixture_metadata,
    )
    from evals.tests.pool_composite_planning_fixture import build_offline_planning
    from evals.tests.pool_composite_prepare_fixture import (
        compile_fixture_documents,
        original_templates,
    )
    from evals.timing_pool import C10_EVIDENCE_ROOT, C10_TRIAL, read_native_observation

    original = read_native_observation(C10_EVIDENCE_ROOT, C10_TRIAL)
    with isolated_native_io(tmp_path):
        data = original_templates()
        from evals.tests.pool_composite_fixture import reconstruct_historical_databases

        reconstruct_historical_databases(data)
        fixture = compile_fixture_documents(
            tmp_path,
            original["actual_conditions"],
            data_override=data,
            baseline=original_account_baseline(data["source"]["budget_path"]),
        )
        materialized = fixture["materialization"]
        register_fixture_metadata(materialized)
        child = materialized["children"][0]
        request = planning_requests(child["planning"])[0]
        result = await build_offline_planning(
            request,
            package_root=data["runtime"]["import_source_dir"],
            budget_path=data["source"]["budget_path"],
            journal_path=child["authority"]["journal_path"],
            authority_sha256=canonical_hash(child["authority"]),
            output_root=tmp_path / "SYNTHETIC-OFFLINE-PLAN-ONLY",
        )
        assert result["state"]["approval"] is None
        assert result["state"]["status"] == "awaiting_approval"
        assert result["actual_provider_requests"] == 0
        assert result["actual_user_approval"] is False
        assert result["model"].ledger[0]["cost_cny"] is not None
        assert (
            result["model"].ledger[0]["model_epoch_id"]
            == request.model_identity_binding.model_epoch_id
        )
        assert len(result["recorder"].records) == 1
        assert result["resources"]["plan_sha256"] == canonical_hash(
            result["state"]["response_plan"]
        )
