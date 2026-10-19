"""Answer-free diagnosis contract shared by investigation and evaluation."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidencesoc.domain.models import AttackOrigin

SIX_ATTACK_TYPES = frozenset(
    {
        "reconnaissance",
        "credential_attack",
        "webshell_upload",
        "remote_command_execution",
        "privilege_escalation",
        "data_exfiltration",
    }
)


class FactClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim_id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)


class StageInstance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    instance_id: str = Field(min_length=1)
    phase: str = Field(min_length=1)
    sequence: int = Field(ge=1)
    evidence_ids: list[str] = Field(default_factory=list)


class Diagnosis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["attack", "benign", "unknown"]
    attack_types: list[str] = Field(default_factory=list)
    taxonomy_status: Literal["mapped", "out_of_taxonomy", "not_applicable", "unknown"]
    origin: AttackOrigin | None = None
    technique_ids: list[str] = Field(default_factory=list)
    stage_instances: list[StageInstance] = Field(default_factory=list)
    claims: list[FactClaim] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent_verdict(self) -> Self:
        if (
            len(set(self.attack_types)) != len(self.attack_types)
            or set(self.attack_types) - SIX_ATTACK_TYPES
        ):
            raise ValueError(
                "attack types must be unique members of the frozen six-class taxonomy"
            )
        if self.verdict != "attack" and (
            self.attack_types or self.taxonomy_status == "mapped"
        ):
            raise ValueError("only an explicit attack can have mapped attack types")
        if self.taxonomy_status == "mapped" and not self.attack_types:
            raise ValueError("mapped diagnosis needs an attack type")
        if self.taxonomy_status == "out_of_taxonomy" and (
            self.verdict != "attack" or self.attack_types
        ):
            raise ValueError("out-of-taxonomy attacks have no mapped attack types")
        if self.verdict == "benign" and self.taxonomy_status != "not_applicable":
            raise ValueError("benign diagnosis has no applicable attack taxonomy")
        identities = [item.instance_id for item in self.stage_instances]
        if len(set(identities)) != len(identities):
            raise ValueError("stage instances must have unique identifiers")
        return self
