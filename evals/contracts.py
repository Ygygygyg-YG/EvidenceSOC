"""Frozen control/worker boundary for Task13. Worker specs never contain gold paths."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

Group = Literal["B0", "B1", "B2", "B3", "A1", "A2", "A3", "A4"]
GROUPS: tuple[Group, ...] = ("B0", "B1", "B2", "B3", "A1", "A2", "A3", "A4")
SHA256 = r"^[0-9a-f]{64}$"
TOOLS = ["search_security_events", "get_alert_context", "lookup_attack_technique"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ModelConfig(Contract):
    requested_model: Literal["deepseek-flash"] = "deepseek-flash"
    published_version: str = "DeepSeek-V4.1-Flash-1017"
    version_checked_at: str = "2026-10-18T13:02:05Z"
    base_url: Literal["https://api.deepseek.com"] = "https://api.deepseek.com"
    thinking: Literal["disabled"] = "disabled"
    temperature: Literal[0] = 0
    max_tokens: int = Field(default=4096, ge=128, le=8192)
    max_context_bytes: int = Field(default=65536, ge=4096, le=262144)
    timeout_seconds: int = Field(default=120, ge=1, le=300)
    provider_seed_supported: Literal[False] = False
    provider_seed: None = None


class SeedPolicy(Contract):
    version: Literal["raw-events-v1"] = "raw-events-v1"
    max_events: int = Field(default=20, ge=1, le=100)
    max_event_bytes: int = Field(default=2048, ge=128, le=4096)
    max_total_bytes: int = Field(default=24576, ge=1024, le=32768)
    knowledge_top_k: int = Field(default=5, ge=1, le=10)


class CallBudget(Contract):
    max_tool_calls_per_round: Literal[3] = 3
    max_tool_calls: Literal[6] = 6
    max_tool_attempts: Literal[3] = 3
    max_model_attempts: Literal[3] = 3
    max_model_calls: int = Field(default=16, ge=1, le=16)


class CapabilityPolicy(Contract):
    allowed_tools: list[str] = Field(default_factory=lambda: TOOLS.copy())
    rag_mode: Literal["hybrid", "semantic_only", "disabled"] = "hybrid"
    verification_enabled: bool = True
    first_round_reserved_calls: int = Field(default=0, ge=0, le=1)
    total_reserved_calls: int = Field(default=0, ge=0, le=1)


def policy_for_group(group: Group) -> CapabilityPolicy:
    if group == "B0":
        return CapabilityPolicy(
            allowed_tools=[], rag_mode="disabled", verification_enabled=False
        )
    if group == "B1":
        return CapabilityPolicy(allowed_tools=[], verification_enabled=False)
    if group == "B2":
        return CapabilityPolicy(verification_enabled=False)
    if group == "A1":
        return CapabilityPolicy(
            allowed_tools=["lookup_attack_technique"],
            first_round_reserved_calls=1,
            total_reserved_calls=1,
        )
    if group == "A2":
        return CapabilityPolicy(allowed_tools=TOOLS[:2], rag_mode="disabled")
    if group == "A3":
        return CapabilityPolicy(rag_mode="semantic_only")
    if group == "A4":
        return CapabilityPolicy(verification_enabled=False)
    if group != "B3":
        raise ValueError(f"unknown group: {group}")
    return CapabilityPolicy()


class WorkerRunSpec(Contract):
    run_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    case_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    group: Group
    config_sha256: str = Field(pattern=SHA256)
    model: ModelConfig = Field(default_factory=ModelConfig)
    capabilities: CapabilityPolicy | None = None
    seed: SeedPolicy = Field(default_factory=SeedPolicy)
    budget: CallBudget = Field(default_factory=CallBudget)
    orchestration_seed: Literal[42] = 42
    replicate: Literal[1] = 1

    @model_validator(mode="after")
    def registered_policy(self) -> Self:
        expected = policy_for_group(self.group)
        if self.capabilities is None:
            self.capabilities = expected
        elif self.capabilities != expected:
            raise ValueError("capabilities must match the preregistered group")
        return self


class PlanRow(Contract):
    row_id: str
    case_id: str
    group: Group
    replicate: Literal[1] = 1
    worker_spec: WorkerRunSpec


class ControllerRunSpec(Contract):
    schema_version: Literal["task13-v1"] = "task13-v1"
    run_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    dataset: Literal["ait", "dedale"]
    split: Literal["development", "validation", "test"] = "development"
    case_root: str
    selection_path: str
    selection_sha256: str = Field(pattern=SHA256)
    admission_paths: list[str] = Field(default_factory=list)
    freeze_manifest: str | None = None
    freeze_sha256: str | None = Field(default=None, pattern=SHA256)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    budget_cny: float = Field(default=100, gt=0, le=100)
    dev_budget_cny: float = Field(default=15, gt=0, le=15)
    reviewer: str = Field(default="user", min_length=1)
    review_window: str = "19:00-00:00 Asia/Shanghai"
    max_attempts: Literal[2] = 2
    rerun_policy: Literal["infra_transport_only_v1"] = "infra_transport_only_v1"
    model: ModelConfig = Field(default_factory=ModelConfig)
    seed: SeedPolicy = Field(default_factory=SeedPolicy)
    call_budget: CallBudget = Field(default_factory=CallBudget)
    rows: list[PlanRow] = Field(default_factory=list)


class AttemptRecord(Contract):
    attempt: int = Field(ge=1, le=2)
    row_id: str
    started_at: str
    finished_at: str | None = None
    execution_status: Literal["started", "completed", "failed", "interrupted"]
    diagnosis_status: Literal["succeeded", "failed", "missing"] = "missing"
    error_category: str | None = None
    approved_rerun: bool = False
    config_sha256: str = Field(pattern=SHA256)
    input_sha256: str = Field(pattern=SHA256)
    output_sha256: str | None = Field(default=None, pattern=SHA256)
    artifact_hashes: dict[str, str] = Field(default_factory=dict)


class AdapterResult(Contract):
    diagnostic_snapshot: dict[str, Any] | None = None
    diagnosis_status: Literal["succeeded", "failed", "missing"] = "missing"
    execution_status: Literal["completed", "failed", "interrupted"] = "completed"
    product_status: str | None = None
    degradation: list[dict[str, Any]] = Field(default_factory=list)
    evidence_registry: dict[str, dict[str, Any]] = Field(default_factory=dict)
    model_ledger: list[dict[str, Any]] = Field(default_factory=list)
    tool_ledger: list[dict[str, Any]] = Field(default_factory=list)
    resources: dict[str, Any] = Field(default_factory=dict)
    verification: dict[str, Any] | None = None
    isolation_evidence: dict[str, Any] | None = None
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    errors: list[dict[str, Any]] = Field(default_factory=list)


def canonical_hash(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()
