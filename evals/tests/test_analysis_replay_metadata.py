"""Only the reviewed optional response audit extension may normalize away."""

import pytest

from evals.adapters import analysis_import

MODELS = "services/backend/src/evidencesoc/agents/models.py"
NODES = "services/backend/src/evidencesoc/agents/nodes/__init__.py"
FIELD = """    no_plan_reason: str | None = Field(
        default=None,
        description="Optional unverified model statement explaining a null response_plan.",
    )
"""
MODEL_BEFORE = (
    "class ResponseOutput(BaseModel):\n    response_plan: ResponsePlan | None\n"
)
MODEL_AFTER = MODEL_BEFORE + FIELD
NODE_BEFORE = """class NodeHandlers:
    async def respond(self, state):
        if invalid:
            return {"response_reason": "invalid_diagnosis_snapshot"}
        if non_attack:
            return {"response_reason": "no_actionable_target"}
        data = output.model_dump(mode="json")
        reason = "model_returned_null"
        generation = state.get("plan_generation", 0)
        return {**data, "response_reason": reason}
"""
BLOCK = """        no_plan_reason = data.get("no_plan_reason")
        if reason != "model_returned_null" or not (
            no_plan_reason and no_plan_reason.strip()
        ):
            no_plan_reason = None
        data["no_plan_reason"] = no_plan_reason
"""
NODE_AFTER = (
    NODE_BEFORE.replace(
        '{"response_reason": "invalid_diagnosis_snapshot"}',
        '{"response_reason": "invalid_diagnosis_snapshot", "no_plan_reason": None, "no_plan_reason_missing": False}',
    )
    .replace(
        '{"response_reason": "no_actionable_target"}',
        '{"response_reason": "no_actionable_target", "no_plan_reason": None, "no_plan_reason_missing": False}',
    )
    .replace(
        '        generation = state.get("plan_generation", 0)\n',
        BLOCK + '        generation = state.get("plan_generation", 0)\n',
    )
    .replace(
        '{**data, "response_reason": reason}',
        '{**data, "response_reason": reason, "no_plan_reason_missing": reason == "model_returned_null" and no_plan_reason is None}',
    )
)


@pytest.mark.parametrize(
    "before,after,path",
    [(MODEL_BEFORE, MODEL_AFTER, MODELS), (NODE_BEFORE, NODE_AFTER, NODES)],
)
def test_only_exact_optional_audit_extension_is_equivalent(before, after, path):
    assert analysis_import._validator_syntax(
        before, path
    ) == analysis_import._validator_syntax(after, path)


@pytest.mark.parametrize(
    "changed,path",
    [
        (MODEL_AFTER.replace("default=None", "default='force'"), MODELS),
        (MODEL_AFTER.replace("str | None", "object | None"), MODELS),
        (NODE_AFTER.replace('data.get("no_plan_reason")', "dangerous_call()"), NODES),
        (
            NODE_AFTER.replace(
                '"no_plan_reason": None', '"no_plan_reason": dangerous_call()'
            ),
            NODES,
        ),
        (
            NODE_AFTER.replace(
                '"no_plan_reason_missing": False', '"no_plan_reason_missing": True'
            ),
            NODES,
        ),
        (
            NODE_AFTER.replace(
                "no_plan_reason is None}", "no_plan_reason is not None}"
            ),
            NODES,
        ),
    ],
)
def test_metadata_lookalikes_do_not_get_a_free_semantic_pass(changed, path):
    original = MODEL_BEFORE if path == MODELS else NODE_BEFORE
    try:
        result = analysis_import._validator_syntax(changed, path)
    except ValueError:
        return
    assert result != analysis_import._validator_syntax(original, path)


@pytest.mark.parametrize(
    "extra",
    [
        "\nclass AnalysisOutput:\n    diagnosis = None\n",
        "\ndef validate_output_citations(output, state):\n    return True\n",
        "\n__import__('os').system('do not execute')\n",
    ],
)
def test_nonmetadata_changes_are_not_normalized_or_executed(extra):
    assert analysis_import._validator_syntax(
        NODE_BEFORE + extra, NODES
    ) != analysis_import._validator_syntax(NODE_BEFORE, NODES)


def test_other_modules_get_no_response_metadata_exemption():
    path = "services/backend/src/evidencesoc/agents/diagnosis.py"
    assert analysis_import._validator_syntax(
        MODEL_BEFORE, path
    ) != analysis_import._validator_syntax(MODEL_AFTER, path)


@pytest.mark.parametrize(
    "changed",
    [
        NODE_AFTER.replace(BLOCK, "").replace(
            "    async def respond(self, state):\n",
            "    async def respond(self, state):\n" + BLOCK,
        ),
        NODE_AFTER.replace(BLOCK, ""),
        NODE_AFTER.replace(
            '"no_plan_reason_missing": False',
            '"no_plan_reason_missing": reason == "model_returned_null" and no_plan_reason is None',
            1,
        ),
        NODE_AFTER.replace(
            '"no_plan_reason_missing": reason == "model_returned_null" and no_plan_reason is None',
            '"no_plan_reason_missing": False',
        ),
        NODE_AFTER.replace(
            '{**data, "response_reason": reason,',
            '{**data, "response_reason": reason, "no_plan_reason": None,',
        ),
        NODE_AFTER.replace(
            '"no_plan_reason_missing": False',
            '"no_plan_reason_missing": False, "no_plan_reason_missing": False',
            1,
        ),
    ],
    ids=[
        "block-before-inputs",
        "missing-block",
        "early-derived",
        "final-false",
        "final-override",
        "duplicate-key",
    ],
)
def test_metadata_cannot_hide_position_or_control_flow_changes(changed):
    try:
        result = analysis_import._validator_syntax(changed, NODES)
    except ValueError:
        return
    assert result != analysis_import._validator_syntax(NODE_BEFORE, NODES)


def test_response_metadata_field_requires_its_reviewed_declaration_position():
    changed = MODEL_AFTER.replace(FIELD, "").replace(
        "class ResponseOutput(BaseModel):\n",
        "class ResponseOutput(BaseModel):\n" + FIELD,
    )
    try:
        result = analysis_import._validator_syntax(changed, MODELS)
    except ValueError:
        return
    assert result != analysis_import._validator_syntax(MODEL_BEFORE, MODELS)
