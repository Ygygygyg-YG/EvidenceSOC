"""Typed controller/worker failures; exception messages never cross the boundary."""


class WorkerInfrastructureError(RuntimeError):
    """Container startup, inspection, probe availability or process failure."""


class WorkerTransportError(RuntimeError):
    """A known transport interruption, eligible for explicitly approved rerun."""


def exception_category(error: Exception) -> str:
    """Only known infrastructure/transport types enable an explicit rerun."""
    import httpx
    from pydantic import ValidationError

    if isinstance(
        error,
        (WorkerTransportError, httpx.TransportError, ConnectionError, TimeoutError),
    ):
        return "transport"
    if isinstance(error, (WorkerInfrastructureError, OSError)):
        return "infrastructure"
    if isinstance(error, ValidationError):
        return "schema"
    return "application"
