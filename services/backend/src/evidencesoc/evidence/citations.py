from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class FactualClaim(BaseModel):
    """One report fact with explicit references in their respective namespaces."""

    model_config = ConfigDict(extra="forbid")

    claim_id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)
    knowledge_chunk_ids: list[str] = Field(default_factory=list)


class ValidatedClaim(FactualClaim):
    status: Literal["supported", "unsupported"]
    reason: Literal["missing_citation", "invalid_citation"] | None = None
    invalid_evidence_ids: list[str] = Field(default_factory=list)
    invalid_knowledge_chunk_ids: list[str] = Field(default_factory=list)


def validate_citations(
    claims: Sequence[FactualClaim | Mapping[str, Any]],
    evidence_ids: Collection[str],
    knowledge_chunk_ids: Collection[str],
) -> list[ValidatedClaim]:
    """Validate citation existence within caller-supplied authorization scopes.

    ``evidence_ids`` must contain only the current incident's evidence and
    ``knowledge_chunk_ids`` only knowledge retrieved or allowed for the report.
    Global existence is insufficient. A claim is unsupported if any reference
    falls outside these sets, even if another reference is valid. This checks
    reference validity, not whether a cited source semantically entails a fact.
    Inputs are neither modified nor shared with the returned models.
    """
    allowed_evidence = frozenset(evidence_ids)
    allowed_knowledge = frozenset(knowledge_chunk_ids)
    results: list[ValidatedClaim] = []
    for raw_claim in claims:
        claim = (
            raw_claim
            if isinstance(raw_claim, FactualClaim)
            else FactualClaim.model_validate(dict(raw_claim))
        )
        invalid_evidence = [
            reference
            for reference in claim.evidence_ids
            if reference not in allowed_evidence
        ]
        invalid_knowledge = [
            reference
            for reference in claim.knowledge_chunk_ids
            if reference not in allowed_knowledge
        ]
        reason: Literal["missing_citation", "invalid_citation"] | None = None
        if not claim.evidence_ids and not claim.knowledge_chunk_ids:
            reason = "missing_citation"
        elif invalid_evidence or invalid_knowledge:
            reason = "invalid_citation"
        results.append(
            ValidatedClaim(
                **claim.model_dump(),
                status="supported" if reason is None else "unsupported",
                reason=reason,
                invalid_evidence_ids=invalid_evidence,
                invalid_knowledge_chunk_ids=invalid_knowledge,
            )
        )
    return results
