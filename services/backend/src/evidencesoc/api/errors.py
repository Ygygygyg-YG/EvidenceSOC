from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status = status
        self.code = code
        self.message = message


def error_response(
    request: Request, status: int, code: str, message: str
) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": message,
                "trace_id": getattr(request.state, "trace_id", None),
            }
        },
    )


def install_error_handlers(app: Any) -> None:
    from evidencesoc.api.storage import StorageConflict

    @app.exception_handler(ApiError)
    async def api_error(request: Request, error: ApiError):
        return error_response(request, error.status, error.code, error.message)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, _error: RequestValidationError):
        # Pydantic errors may contain the original request and secrets.
        return error_response(
            request, 422, "INVALID_REQUEST", "Request validation failed."
        )

    @app.exception_handler(StorageConflict)
    async def conflict(request: Request, _error: StorageConflict):
        return error_response(
            request, 409, "CONFLICT", "Request conflicts with existing state."
        )

    @app.exception_handler(LookupError)
    async def not_found(request: Request, _error: LookupError):
        return error_response(
            request, 404, "NOT_FOUND", "Requested resource was not found."
        )

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, error: HTTPException):
        codes = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}
        return error_response(
            request,
            error.status_code,
            codes.get(error.status_code, "HTTP_ERROR"),
            "Request could not be processed.",
        )

    @app.exception_handler(Exception)
    async def internal_error(request: Request, _error: Exception):
        return error_response(
            request,
            503,
            "DEPENDENCY_UNAVAILABLE",
            "A required dependency is unavailable.",
        )
