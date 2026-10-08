from __future__ import annotations

from contextlib import closing
from datetime import UTC, datetime

from evidencesoc.api.demo_session import require_demo_reviewer
from evidencesoc.config import Settings
from evidencesoc.main import create_app
from fastapi import Request
from fastapi.testclient import TestClient

FRONTEND_ORIGIN = "http://127.0.0.1:3000"


def demo_client(*, client_host: str = "127.0.0.1") -> TestClient:
    app = create_app(
        settings=Settings(
            _env_file=None,
            demo_session_enabled=True,
            frontend_origin=FRONTEND_ORIGIN,
        )
    )
    return TestClient(app, client=(client_host, 50000))


def test_local_demo_login_issues_server_owned_strict_cookie_and_session_view() -> None:
    with closing(demo_client()) as client:
        login = client.post("/api/v1/session/demo", headers={"Origin": FRONTEND_ORIGIN})
        assert login.status_code == 200, login.text
        view = login.json()
        assert view["actor_id"] == "demo-reviewer"
        assert view["role"] == "reviewer"
        assert view["allowed_actions"] == ["approve", "reject"]
        assert datetime.fromisoformat(view["expires_at"]).tzinfo == UTC
        cookie = login.headers["set-cookie"]
        assert "evidencesoc_demo_session=" in cookie
        assert "httponly" in cookie.lower()
        assert "samesite=strict" in cookie.lower()
        assert "path=/" in cookie.lower()
        assert "domain=" not in cookie.lower()
        assert login.headers["cache-control"] == "no-store"

        current = client.get("/api/v1/session")
        assert current.status_code == 200, current.text
        assert current.json() == view
        assert current.headers["cache-control"] == "no-store"


def test_local_demo_login_rejects_missing_or_untrusted_origin() -> None:
    with closing(demo_client()) as client:
        for origin in (None, "https://evil.example", "http://127.0.0.1:3001"):
            headers = {} if origin is None else {"Origin": origin}
            result = client.post("/api/v1/session/demo", headers=headers)
            assert result.status_code == 403, result.text
        assert client.get("/api/v1/session").status_code == 401


def test_local_demo_session_rejects_remote_clients_even_with_spoofed_forwarded_ip() -> (
    None
):
    with closing(demo_client(client_host="203.0.113.7")) as client:
        result = client.post(
            "/api/v1/session/demo",
            headers={
                "Origin": FRONTEND_ORIGIN,
                "X-Forwarded-For": "127.0.0.1",
            },
        )
        assert result.status_code == 403, result.text


def test_demo_session_is_disabled_without_explicit_setting() -> None:
    app = create_app(settings=Settings(_env_file=None, demo_session_enabled=False))
    with closing(TestClient(app, client=("127.0.0.1", 50000))) as client:
        result = client.post(
            "/api/v1/session/demo", headers={"Origin": FRONTEND_ORIGIN}
        )
        assert result.status_code == 403, result.text
        start = client.post(
            "/api/v1/investigations",
            json={"alert_id": "AL-disabled", "mode": "rules"},
            headers={"Origin": FRONTEND_ORIGIN, "Idempotency-Key": "disabled-start"},
        )
        assert start.status_code == 403, start.text
        assert start.json()["error"]["code"] == "DEMO_SESSION_DISABLED"
        raw = client.get("/api/v1/incidents/IN-disabled/evidence/EV-disabled")
        assert raw.status_code == 403, raw.text
        assert raw.json()["error"]["code"] == "DEMO_SESSION_DISABLED"


def test_demo_session_rejects_tampered_and_expired_cookie() -> None:
    with closing(demo_client()) as client:
        from evidencesoc.api.demo_session import DemoSessionManager

        clock = {"now": 1_800_000_000}
        client.app.state.demo_sessions = DemoSessionManager(
            client.app.state.demo_session_settings,
            clock=lambda: clock["now"],
        )
        login = client.post("/api/v1/session/demo", headers={"Origin": FRONTEND_ORIGIN})
        assert login.status_code == 200, login.text
        token = client.cookies.get("evidencesoc_demo_session")
        assert token

        payload, signature = token.split(".", 1)
        changed = "A" if signature[0] != "A" else "B"
        client.cookies.set(
            "evidencesoc_demo_session", payload + "." + changed + signature[1:]
        )
        assert client.get("/api/v1/session").status_code == 401

        client.cookies.set("evidencesoc_demo_session", "garbage.%")
        assert client.get("/api/v1/session").status_code == 401

        client.cookies.set("evidencesoc_demo_session", token)
        clock["now"] += 1801
        assert client.get("/api/v1/session").status_code == 401


def test_demo_session_from_one_app_is_invalid_after_restart() -> None:
    with closing(demo_client()) as first:
        result = first.post("/api/v1/session/demo", headers={"Origin": FRONTEND_ORIGIN})
        assert result.status_code == 200, result.text
        token = first.cookies.get("evidencesoc_demo_session")
        assert token

    with closing(demo_client()) as second:
        second.cookies.set("evidencesoc_demo_session", token)
        assert second.get("/api/v1/session").status_code == 401


def test_reviewer_verifier_requires_origin_and_returns_server_identity() -> None:
    app = create_app(settings=Settings(_env_file=None, demo_session_enabled=True))

    @app.post("/test/reviewer")
    async def reviewer(request: Request):
        return {"actor_id": require_demo_reviewer(request)}

    with closing(TestClient(app, client=("127.0.0.1", 50000))) as client:
        headers = {"Origin": FRONTEND_ORIGIN}
        assert client.post("/test/reviewer", headers=headers).status_code == 401
        assert client.post("/api/v1/session/demo", headers=headers).status_code == 200
        assert client.post("/test/reviewer").status_code == 403
        assert client.post("/test/reviewer", headers=headers).json() == {
            "actor_id": "demo-reviewer"
        }
