from __future__ import annotations


class ToolExecutionError(RuntimeError):
    code = "DEPENDENCY_UNAVAILABLE"
    public_message = "dependency unavailable"


class ToolDependencyError(ToolExecutionError):
    pass


class ToolDependencyTimeout(ToolExecutionError):
    code = "DEPENDENCY_TIMEOUT"
    public_message = "dependency timed out"


class ToolNotFoundError(ToolExecutionError):
    code = "NOT_FOUND"
    public_message = "resource not found"
