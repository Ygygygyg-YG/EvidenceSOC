from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from ipaddress import ip_address, ip_network
from typing import Any, Literal
from urllib.parse import unquote

from evidencesoc.agents.models import (
    AnalysisOutput,
    AttackStep,
    ReconstructionOutput,
    ResponseOutput,
    SimulatedAction,
)
from evidencesoc.domain.models import AttackClassification, AttackOrigin, ResponsePlan

SQL_PATTERN = re.compile(
    r"\bunion\s+(?:all\s+)?select\b|\b(?:or|and)\s+['\"]?1['\"]?\s*=\s*['\"]?1\b|\b(?:sleep|benchmark)\s*\(",
    re.IGNORECASE,
)
OBSERVED_FIELDS = frozenset(
    {
        "source_ip",
        "src_ip",
        "client_ip",
        "remote_addr",
        "destination_ip",
        "dest_ip",
        "host",
        "hostname",
        "destination_host",
        "service",
        "event_type",
        "timestamp",
        "request_uri",
        "uri",
        "url",
        "path",
        "request",
        "query_string",
        "message",
        "body",
        "user",
        "username",
        "account",
        "status",
        "status_code",
    }
)


def observed_raw(item: dict[str, Any]) -> dict[str, Any]:
    raw = item.get("raw", {})
    if not isinstance(raw, dict):
        return {}
    result = {key: value for key, value in raw.items() if key in OBSERVED_FIELDS}
    http = raw.get("http")
    if isinstance(http, dict):
        result["http"] = {
            key: value
            for key, value in http.items()
            if key in {"method", "path", "status_code"}
        }
    return result


def source_ip(raw: dict[str, Any]) -> str | None:
    for key in ("source_ip", "src_ip", "client_ip", "remote_addr"):
        value = raw.get(key)
        if isinstance(value, str):
            try:
                return str(ip_address(value))
            except ValueError:
                continue
    return None


def source_host(raw: dict[str, Any]) -> str | None:
    for key in ("host", "hostname", "destination_host"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def source_scope(address: str | None) -> Literal["external", "internal", "unknown"]:
    if address is None:
        return "unknown"
    parsed = ip_address(address)
    internal = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
    if any(parsed in ip_network(network) for network in internal):
        return "internal"
    return "external" if parsed.is_global else "unknown"


def sql_observations(state: dict[str, Any]) -> list[dict[str, Any]]:
    observations = []
    for item in state.get("evidence", []):
        raw = observed_raw(item)
        content = " ".join(
            value
            for key, value in raw.items()
            if key
            in {
                "request_uri",
                "uri",
                "url",
                "path",
                "request",
                "query_string",
                "message",
                "body",
            }
            and isinstance(value, str)
        )
        http = raw.get("http", {})
        if isinstance(http, dict) and isinstance(http.get("path"), str):
            content += " " + http["path"]
        if SQL_PATTERN.search(unquote(content)):
            observations.append(item)
    return sorted(
        observations, key=lambda item: datetime.fromisoformat(item["observed_at"])
    )


def technique_ids(state: dict[str, Any]) -> list[str]:
    return (
        ["T1190"]
        if any(
            item.get("technique_id") == "T1190"
            and isinstance(item.get("knowledge_chunk_id"), str)
            and item.get("knowledge_chunk_id")
            and isinstance(item.get("source_uri"), str)
            and item.get("source_uri", "").startswith(
                "https://attack.mitre.org/techniques/T1190/"
            )
            for item in state.get("knowledge", [])
        )
        else []
    )


def analyze(state: dict[str, Any]) -> AnalysisOutput:
    items = sql_observations(state)
    if not items:
        return AnalysisOutput(origin=None, classification=None)
    raw = observed_raw(items[0])
    address = source_ip(raw)
    when = datetime.fromisoformat(items[0]["observed_at"])
    ids = [item["evidence_id"] for item in items]
    return AnalysisOutput(
        origin=AttackOrigin(
            observed_source_ip=address,
            entry_host=source_host(raw),
            entry_service=raw.get("service")
            if isinstance(raw.get("service"), str)
            else None,
            first_seen_at=when,
            source_scope=source_scope(address),
            confidence=0.8,
            evidence_ids=[items[0]["evidence_id"]],
        ),
        classification=AttackClassification(
            primary_type="sql_injection",
            attack_types=["sql_injection"],
            attack_phase="initial_access",
            technique_ids=technique_ids(state),
            confidence=0.8,
            evidence_ids=ids,
        ),
    )


def reconstruct(state: dict[str, Any]) -> ReconstructionOutput:
    classification = state.get("classification")
    if not classification or classification.get("primary_type") in {None, "unknown"}:
        return ReconstructionOutput(attack_steps=[])
    techniques = technique_ids(state)
    steps = [
        AttackStep(
            attack_step_id="AS-"
            + sha256(
                (state["incident_id"] + "|" + item["evidence_id"]).encode()
            ).hexdigest()[:24],
            sequence=index,
            phase="initial_access",
            technique_id=techniques[0] if techniques else None,
            description="Observed request contains a SQL injection pattern; successful exploitation is unconfirmed.",
            occurred_at=datetime.fromisoformat(item["observed_at"]),
            evidence_ids=[item["evidence_id"]],
        )
        for index, item in enumerate(sql_observations(state), start=1)
    ]
    return ReconstructionOutput(attack_steps=steps)


def respond(state: dict[str, Any]) -> ResponseOutput:
    origin = state.get("origin")
    classification = state.get("classification")
    if (
        not origin
        or not classification
        or classification.get("primary_type") in {None, "unknown"}
    ):
        return ResponseOutput(response_plan=None)
    address = origin.get("observed_source_ip")
    if not address:
        return ResponseOutput(response_plan=None)
    ids = list(classification["evidence_ids"])
    digest = sha256((state["incident_id"] + "|" + "|".join(ids)).encode()).hexdigest()[
        :24
    ]
    action = SimulatedAction(
        action="block_ip_simulated",
        target=address,
        risk="A source IP can represent multiple legitimate clients.",
        impact="Only a simulated block is recorded; no real traffic changes.",
        preview=f"Preview a simulated block for observed source {address}.",
        rollback=f"Remove the simulated block overlay for {address}.",
        verification_query={"filters": {"source_ip": address}, "limit": 100},
        action_id=f"ACT-{digest}-1",
        type="block_ip_simulated",
        parameters={"source_ip": address},
        expected_effect="Record a simulated block for this source IP without changing traffic.",
        rollback_ref=f"RB-{digest}",
        evidence_ids=ids,
    )
    generated_at = datetime.now(UTC)
    return ResponseOutput(
        response_plan=ResponsePlan(
            response_plan_id=f"RP-{digest}",
            incident_id=state["incident_id"],
            summary="Review the SQL-pattern observation and approve a simulated response.",
            actions=[action.model_dump(mode="json")],
            created_at=generated_at,
            evidence_ids=ids,
            risk_level="medium",
            risk_reason=action.risk,
            affected_assets=[address],
            business_impact=action.impact,
            expires_at=generated_at + timedelta(minutes=30),
            rollback_steps=[
                {
                    "step_id": f"RB-{digest}",
                    "description": action.rollback,
                    "target": address,
                    "expected_result": "The simulated block overlay is removed.",
                    "evidence_ids": ids,
                }
            ],
            validation_checks=[
                {
                    "check_id": f"VC-{digest}",
                    "description": "Requery the observed source after the simulated action.",
                    "target": address,
                    "expected_result": "Compare fresh query results with cited baseline evidence.",
                    "query": action.verification_query,
                    "evidence_ids": ids,
                }
            ],
        )
    )


def matching_target(item: dict[str, Any], action: SimulatedAction) -> bool:
    raw = observed_raw(item)
    if action.action == "block_ip_simulated":
        return source_ip(raw) == action.target
    if action.action == "isolate_host_simulated":
        return source_host(raw) == action.target
    return any(raw.get(key) == action.target for key in ("user", "username", "account"))


def checked_timestamp(state: dict[str, Any], items: list[dict[str, Any]]) -> datetime:
    values = [datetime.fromisoformat(item["observed_at"]) for item in items]
    return max(values) if values else datetime.now(UTC)
