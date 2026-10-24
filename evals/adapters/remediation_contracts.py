"""Answer-free worker requests for the separately registered Task13 supplement."""

from __future__ import annotations

import re
from hashlib import sha256
from typing import Literal, Self

from pydantic import Field, model_validator

from evals.contracts import (
    SHA256,
    CallBudget,
    Contract,
    ModelConfig,
    SeedPolicy,
    WorkerRunSpec,
    canonical_hash,
)

CAMPAIGN = "task13-repair-202610-v2"
ENTRY_PROMPT = (
    "Use only supplied observable evidence and retrieved knowledge. Keep facts "
    "traceable to registered evidence_ids. Keep unknown when the evidence is "
    "insufficient. Never read control-side labels or case strata."
)


class RemediationRequest(Contract):
    schema_version: Literal["task13-remediation-worker-v2"] = (
        "task13-remediation-worker-v2"
    )
    campaign_id: Literal["task13-repair-202610-v2"] = CAMPAIGN
    run_id: str
    case_id: str = Field(pattern=r"^(?:ait-[0-9a-f]{24}|dedale-[0-9a-f]{16})$")
    group: Literal["B2", "B3"]
    slot_id: str = Field(pattern=r"^(?:development|regression)-[0-9a-f]{24}$")
    attempt: Literal[1] = 1
    purpose: Literal["development", "regression"]
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=SHA256)
    config_sha256: str = Field(pattern=SHA256)
    agent_sha256: str = Field(pattern=SHA256)
    budget_identity: dict
    rag_mode: Literal["disabled", "semantic_only", "hybrid"] | None = None
    initial_query: str | None = Field(default=None, max_length=300)
    initial_query_sha256: str | None = Field(default=None, pattern=SHA256)
    repeat: int = Field(default=1, ge=1, le=3)
    entry_prompt: Literal[ENTRY_PROMPT] = ENTRY_PROMPT
    model: ModelConfig = Field(default_factory=ModelConfig)
    seed: SeedPolicy = Field(default_factory=SeedPolicy)
    budget: CallBudget = Field(default_factory=CallBudget)

    @model_validator(mode="after")
    def registered_scope(self) -> Self:
        identity = self.budget_identity
        if (
            set(identity)
            != {
                "schema_version",
                "baseline_count",
                "baseline_max_rowid",
                "baseline_sha256",
            }
            or identity.get("schema_version") != "task13-original-budget-identity-v1"
            or type(identity.get("baseline_count")) is not int
            or identity["baseline_count"] < 1
            or type(identity.get("baseline_max_rowid")) is not int
            or identity["baseline_max_rowid"] < identity["baseline_count"]
            or not isinstance(identity.get("baseline_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", identity["baseline_sha256"])
        ):
            raise ValueError("original budget history identity is required")
        expected = CAMPAIGN + "-" + canonical_hash([self.slot_id, self.attempt])[:16]
        if self.run_id != expected or not self.slot_id.startswith(self.purpose + "-"):
            raise ValueError("run identity or purpose differs from the registered slot")
        if self.purpose == "development":
            if self.group != "B3" or self.rag_mode is None or not self.initial_query:
                raise ValueError(
                    "development requires its fixed query and RAG condition"
                )
            if (
                sha256(self.initial_query.encode()).hexdigest()
                != self.initial_query_sha256
            ):
                raise ValueError("fixed initial query hash differs")
        elif (
            self.rag_mode is not None
            or self.initial_query is not None
            or self.initial_query_sha256 is not None
            or self.repeat != 1
        ):
            raise ValueError("regression must preserve registered B2/B3 policies")
        return self

    def worker_spec(self) -> WorkerRunSpec:
        return WorkerRunSpec(
            run_id=self.run_id,
            case_id=self.case_id,
            group=self.group,
            config_sha256=self.config_sha256,
            model=self.model,
            seed=self.seed,
            budget=self.budget,
        )

    def budget_binding(self) -> dict:
        return {
            key: getattr(self, key)
            for key in (
                "campaign_id",
                "case_id",
                "group",
                "attempt",
                "purpose",
                "source_sha256",
                "config_sha256",
            )
        }
