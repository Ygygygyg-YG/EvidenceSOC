"""Cooperative request budget propagated into synchronous dependency workers."""
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Event
from time import monotonic

from evidencesoc.tools.errors import ToolDependencyTimeout


@dataclass
class ExecutionBudget:
    deadline: float
    cancelled: Event = field(default_factory=Event)

    def remaining(self) -> float:
        remaining = self.deadline - monotonic()
        if self.cancelled.is_set() or remaining <= 0:
            raise ToolDependencyTimeout("dependency timed out")
        return remaining


CURRENT_BUDGET: ContextVar[ExecutionBudget | None] = ContextVar("execution_budget", default=None)
CALL_DEADLINE: ContextVar[float | None] = ContextVar("call_deadline", default=None)


def check_execution() -> float | None:
    budget = CURRENT_BUDGET.get()
    return budget.remaining() if budget is not None else None
