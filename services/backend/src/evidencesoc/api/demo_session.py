"""Short-lived, server-owned reviewer sessions for explicitly enabled local demos."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from evidencesoc.api.errors import ApiError
from evidencesoc.api.models import ERROR_RESPONSES, ErrorEnvelope
from evidencesoc.config import Settings

COOKIE_NAME = "evidencesoc_demo_session"
ACTOR_ID: Literal["demo-reviewer"] = "demo-reviewer"
SESSION_LIFETIME_SECONDS = 30 * 60


class DemoSessionView(BaseModel):
    actor_id: Literal["demo-reviewer"]
    role: Literal["reviewer"]
    allowed_actions: tuple[Literal["approve", "reject"], Literal["approve", "reject"]]
    expires_at: datetime


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )


class DemoSessionManager:
    def __init__(
        self,
        settings: Settings,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._enabled = settings.demo_session_enabled
        self._frontend_origin = settings.frontend_origin
        self._clock = clock
        self._secret = secrets.token_bytes(32)

    def _ensure_local(self, request: Request) -> None:
        if not self._enabled:
            raise ApiError(403, "DEMO_SESSION_DISABLED", "Local demo mode is disabled.")
        client_host = request.client.host if request.client else ""
        try:
            ip = ipaddress.ip_address(client_host)
        except ValueError:
            ip = None
        mapped_ip = getattr(ip, "ipv4_mapped", None)
        if ip is None or not (ip.is_loopback or (mapped_ip and mapped_ip.is_loopback)):
            raise ApiError(
                403, "LOCAL_ONLY", "Local demo mode requires a loopback client."
            )

    def _ensure_origin(self, request: Request) -> None:
        if request.headers.get("origin") != self._frontend_origin:
            raise ApiError(403, "UNTRUSTED_ORIGIN", "Request origin is not allowed.")

    def issue(self, request: Request) -> tuple[str, DemoSessionView]:
        self._ensure_local(request)
        self._ensure_origin(request)
        issued_at = int(self._clock())
        expires_at = issued_at + SESSION_LIFETIME_SECONDS
        claims = {
            "v": 1,
            "sub": ACTOR_ID,
            "iat": issued_at,
            "exp": expires_at,
            "nonce": secrets.token_urlsafe(16),
        }
        payload = _encode(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        )
        signature = _encode(
            hmac.digest(self._secret, payload.encode("ascii"), hashlib.sha256)
        )
        return payload + "." + signature, self._view(expires_at)

    def require(self, request: Request, *, check_origin: bool) -> DemoSessionView:
        self._ensure_local(request)
        if check_origin:
            self._ensure_origin(request)
        token = request.cookies.get(COOKIE_NAME)
        if not token or len(token) > 2048 or token.count(".") != 1:
            raise ApiError(401, "SESSION_REQUIRED", "A valid demo session is required.")
        payload, signature = token.split(".", 1)
        try:
            actual = _decode(signature)
            expected = hmac.digest(
                self._secret, payload.encode("ascii"), hashlib.sha256
            )
            if not hmac.compare_digest(actual, expected):
                raise ValueError("Invalid signature")
            claims = json.loads(_decode(payload))
        except (ValueError, UnicodeError, TypeError, binascii.Error):
            raise ApiError(
                401, "SESSION_REQUIRED", "A valid demo session is required."
            ) from None
        now = int(self._clock())
        if (
            not isinstance(claims, dict)
            or set(claims) != {"v", "sub", "iat", "exp", "nonce"}
            or claims["v"] != 1
            or claims["sub"] != ACTOR_ID
            or type(claims["iat"]) is not int
            or type(claims["exp"]) is not int
            or not isinstance(claims["nonce"], str)
            or claims["exp"] - claims["iat"] != SESSION_LIFETIME_SECONDS
            or not claims["iat"] <= now < claims["exp"]
        ):
            raise ApiError(401, "SESSION_REQUIRED", "A valid demo session is required.")
        return self._view(claims["exp"])

    @staticmethod
    def _view(expires_at: int) -> DemoSessionView:
        return DemoSessionView(
            actor_id=ACTOR_ID,
            role="reviewer",
            allowed_actions=("approve", "reject"),
            expires_at=datetime.fromtimestamp(expires_at, UTC),
        )


def require_demo_reviewer(request: Request) -> str:
    """Validate a write request and return the only permitted local demo actor."""
    manager: DemoSessionManager = request.app.state.demo_sessions
    return manager.require(request, check_origin=True).actor_id


def require_demo_session(
    request: Request, *, check_origin: bool = False
) -> DemoSessionView:
    """Authorize a sensitive API request with a server-owned local demo session."""
    manager: DemoSessionManager = request.app.state.demo_sessions
    return manager.require(request, check_origin=check_origin)


router = APIRouter(
    prefix="/api/v1/session",
    responses={
        **ERROR_RESPONSES,
        401: {"model": ErrorEnvelope},
        403: {"model": ErrorEnvelope},
    },
)


@router.post("/demo", response_model=DemoSessionView)
async def create_demo_session(request: Request, response: Response):
    manager: DemoSessionManager = request.app.state.demo_sessions
    token, view = manager.issue(request)
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=SESSION_LIFETIME_SECONDS,
        httponly=True,
        samesite="strict",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return view


@router.get("", response_model=DemoSessionView)
async def get_demo_session(request: Request, response: Response):
    manager: DemoSessionManager = request.app.state.demo_sessions
    view = manager.require(request, check_origin=False)
    response.headers["Cache-Control"] = "no-store"
    return view
