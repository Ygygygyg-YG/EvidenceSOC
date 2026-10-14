from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from evidencesoc.evidence.citations import FactualClaim, validate_citations
from pydantic import ValidationError

EVIDENCE_ID = "EV-01J8ZW4AAA0ABCDEFGHJKMNPQR"
OTHER_EVIDENCE_ID = "EV-01J8ZW4AAA1ABCDEFGHJKMNPQR"
KNOWLEDGE_ID = "KC-attack-v19.2-T1048.003"
OTHER_KNOWLEDGE_ID = "KC-attack-v19.2-T1071.004"


def make_claim(**changes: Any) -> FactualClaim:
    return FactualClaim(
        **{
            "claim_id": "origin-1",
            "text": "The source sent DNS queries containing encoded data.",
            **changes,
        }
    )


@pytest.mark.parametrize(
    ("evidence", "knowledge"),
    [([EVIDENCE_ID], []), ([], [KNOWLEDGE_ID]), ([EVIDENCE_ID], [KNOWLEDGE_ID])],
    ids=["incident-evidence", "retrieved-knowledge", "both"],
)
def test_existing_in_scope_citations_support_claim(
    evidence: list[str], knowledge: list[str]
) -> None:
    claim = make_claim(evidence_ids=evidence, knowledge_chunk_ids=knowledge)

    result = validate_citations([claim], {EVIDENCE_ID}, {KNOWLEDGE_ID})[0]

    assert result.claim_id == claim.claim_id
    assert result.text == claim.text
    assert result.evidence_ids == evidence
    assert result.knowledge_chunk_ids == knowledge
    assert result.status == "supported"
    assert result.reason is None
    assert result.invalid_evidence_ids == []
    assert result.invalid_knowledge_chunk_ids == []


def test_claim_without_citation_is_unsupported() -> None:
    result = validate_citations([make_claim()], {EVIDENCE_ID}, {KNOWLEDGE_ID})[0]

    assert result.status == "unsupported"
    assert result.reason == "missing_citation"


@pytest.mark.parametrize(
    ("evidence", "knowledge", "invalid_evidence", "invalid_knowledge"),
    [
        ([OTHER_EVIDENCE_ID], [], [OTHER_EVIDENCE_ID], []),
        ([], [OTHER_KNOWLEDGE_ID], [], [OTHER_KNOWLEDGE_ID]),
        ([EVIDENCE_ID, OTHER_EVIDENCE_ID], [], [OTHER_EVIDENCE_ID], []),
        ([EVIDENCE_ID], [OTHER_KNOWLEDGE_ID], [], [OTHER_KNOWLEDGE_ID]),
        ([OTHER_EVIDENCE_ID], [KNOWLEDGE_ID], [OTHER_EVIDENCE_ID], []),
        ([], [KNOWLEDGE_ID, OTHER_KNOWLEDGE_ID], [], [OTHER_KNOWLEDGE_ID]),
    ],
    ids=[
        "unknown-evidence",
        "unknown-knowledge",
        "mixed-evidence",
        "valid-evidence-invalid-knowledge",
        "invalid-evidence-valid-knowledge",
        "mixed-knowledge",
    ],
)
def test_any_invalid_reference_makes_the_entire_claim_unsupported(
    evidence: list[str],
    knowledge: list[str],
    invalid_evidence: list[str],
    invalid_knowledge: list[str],
) -> None:
    claim = make_claim(evidence_ids=evidence, knowledge_chunk_ids=knowledge)

    result = validate_citations([claim], {EVIDENCE_ID}, {KNOWLEDGE_ID})[0]

    assert result.status == "unsupported"
    assert result.reason == "invalid_citation"
    assert result.invalid_evidence_ids == invalid_evidence
    assert result.invalid_knowledge_chunk_ids == invalid_knowledge


def test_caller_scope_controls_support_even_for_globally_existing_ids() -> None:
    claim = make_claim(
        evidence_ids=[OTHER_EVIDENCE_ID], knowledge_chunk_ids=[OTHER_KNOWLEDGE_ID]
    )

    result = validate_citations([claim], {EVIDENCE_ID}, {KNOWLEDGE_ID})[0]

    assert result.status == "unsupported"
    assert result.invalid_evidence_ids == [OTHER_EVIDENCE_ID]
    assert result.invalid_knowledge_chunk_ids == [OTHER_KNOWLEDGE_ID]


def test_citation_namespaces_are_checked_separately() -> None:
    claim = make_claim(evidence_ids=[KNOWLEDGE_ID], knowledge_chunk_ids=[EVIDENCE_ID])

    result = validate_citations([claim], {EVIDENCE_ID}, {KNOWLEDGE_ID})[0]

    assert result.status == "unsupported"
    assert result.invalid_evidence_ids == [KNOWLEDGE_ID]
    assert result.invalid_knowledge_chunk_ids == [EVIDENCE_ID]


def test_batch_preserves_order_and_validates_each_claim_independently() -> None:
    claims = [
        make_claim(claim_id="valid", evidence_ids=[EVIDENCE_ID, EVIDENCE_ID]),
        make_claim(claim_id="missing"),
        make_claim(claim_id="invalid", evidence_ids=[OTHER_EVIDENCE_ID]),
    ]

    results = validate_citations(claims, {EVIDENCE_ID}, set())

    assert [result.claim_id for result in results] == ["valid", "missing", "invalid"]
    assert [result.status for result in results] == [
        "supported",
        "unsupported",
        "unsupported",
    ]
    assert results[0].evidence_ids == [EVIDENCE_ID, EVIDENCE_ID]
    assert validate_citations([], set(), set()) == []


def test_validation_accepts_structured_mappings_without_mutating_or_aliasing() -> None:
    claim = make_claim(evidence_ids=[EVIDENCE_ID])
    mapping = make_claim(
        claim_id="mapped", knowledge_chunk_ids=[KNOWLEDGE_ID]
    ).model_dump()
    claims = [claim, mapping]
    original_claim = claim.model_dump()
    original_mapping = deepcopy(mapping)
    evidence_allowlist = [EVIDENCE_ID]
    knowledge_allowlist = [KNOWLEDGE_ID]

    results = validate_citations(claims, evidence_allowlist, knowledge_allowlist)
    results[0].evidence_ids.append(OTHER_EVIDENCE_ID)
    results[1].knowledge_chunk_ids.append(OTHER_KNOWLEDGE_ID)

    assert claim.model_dump() == original_claim
    assert mapping == original_mapping
    assert evidence_allowlist == [EVIDENCE_ID]
    assert knowledge_allowlist == [KNOWLEDGE_ID]


@pytest.mark.parametrize(
    "changes",
    [
        {"claim_id": ""},
        {"text": ""},
        {"evidence_ids": "not-a-list"},
        {"supported": True},
    ],
)
def test_claim_requires_valid_structure(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_claim(**changes)
