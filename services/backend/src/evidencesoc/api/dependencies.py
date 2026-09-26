from fastapi import Request

from evidencesoc.api.errors import ApiError


def get_runner(request: Request):
    runner = getattr(request.app.state, "runner", None)
    if runner is None:
        raise ApiError(503, "DEPENDENCY_UNAVAILABLE", "API dependencies are not ready.")
    return runner
