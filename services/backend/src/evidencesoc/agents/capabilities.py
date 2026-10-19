"""Trusted run capabilities; model output cannot enable a disabled capability."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Literal

from evidencesoc.tools.policy import ALLOWED_TOOLS

RetrievalMode = Literal["hybrid", "semantic_only", "disabled"]


@dataclass(frozen=True)
class InvestigationCapabilities:
    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset(ALLOWED_TOOLS)
    )
    rag_mode: RetrievalMode = "hybrid"
    verification_enabled: bool = True
    first_round_reserved_calls: int = 0
    total_reserved_calls: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_tools", frozenset(self.allowed_tools))
        if not self.allowed_tools <= ALLOWED_TOOLS:
            raise ValueError("capabilities contain an unsupported tool")
        if self.rag_mode not in {"hybrid", "semantic_only", "disabled"}:
            raise ValueError("unsupported retrieval mode")
        if (
            not 0 <= self.first_round_reserved_calls <= 3
            or not 0 <= self.total_reserved_calls <= 6
        ):
            raise ValueError("reserved slots exceed the original budget")

    def require_tool(self, name: str) -> None:
        if name not in self.allowed_tools or (
            name == "lookup_attack_technique" and self.rag_mode == "disabled"
        ):
            raise PermissionError("tool disabled by investigation capabilities")


_CAPABILITIES: ContextVar[InvestigationCapabilities | None] = ContextVar(
    "investigation_capabilities", default=None
)


def current_capabilities() -> InvestigationCapabilities | None:
    return _CAPABILITIES.get()


@contextmanager
def capability_scope(policy: InvestigationCapabilities | None) -> Iterator[None]:
    token = _CAPABILITIES.set(policy)
    try:
        yield
    finally:
        _CAPABILITIES.reset(token)


def retrieval_mode(mode: RetrievalMode | None = None) -> RetrievalMode:
    policy = current_capabilities()
    if policy is not None:
        if policy.rag_mode == "disabled":
            return "disabled"
        if policy.rag_mode == "semantic_only":
            return "disabled" if mode == "disabled" else "semantic_only"
    selected = mode or "hybrid"
    if selected not in {"hybrid", "semantic_only", "disabled"}:
        raise ValueError("unsupported retrieval mode")
    return selected
