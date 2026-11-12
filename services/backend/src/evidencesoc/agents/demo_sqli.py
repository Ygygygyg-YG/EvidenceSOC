"""Trusted, local-only control observations for the registered SQL injection demo."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from evidencesoc.agents.verification import EffectObservation
from evidencesoc.domain.models import EvidenceItem, ResponsePlan
from evidencesoc.domain.response_action import SimulatedAction
from evidencesoc.ids import new_ulid
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.persistence.event_repository import EvidenceRepository
from evidencesoc.persistence.tables import (
    AlertTable,
    EvidenceItemTable,
    IncidentTable,
    SecurityEventTable,
)

_ALERT = re.compile(r"AL-SQLI-DEMO-([0-9a-f]{32})-(FIXTURE|DEEPSEEK|REJECT)")
_TARGET = "203.0.113.42"
_SOURCE = "simulated-control-observation"


class DemoRegistrationError(ValueError):
    """A reserved demo alert does not match its local registration."""


def is_demo_alert(alert_id: str) -> bool:
    return _ALERT.fullmatch(alert_id) is not None


class SqlInjectionDemo:
    def __init__(
        self, directory: Path, mode: str | None, sessions: Callable[[], Session]
    ) -> None:
        self.directory, self.mode, self.sessions = directory, mode, sessions

    async def authorize(self, incident_id: str, alerts: list[dict]) -> str | None:
        if not alerts or not is_demo_alert(alerts[0]["alert_id"]):
            return None
        if len(alerts) != 1:
            raise DemoRegistrationError("demo requires one registered alert")
        return await asyncio.to_thread(
            self._registered_namespace, incident_id, alerts[0]["alert_id"]
        )

    async def authorize_start(
        self, alert_id: str | None, incident_id: str | None
    ) -> None:
        if alert_id is None or is_demo_alert(alert_id):
            await asyncio.to_thread(self._authorize_start, alert_id, incident_id)

    def _authorize_start(self, alert_id: str | None, incident_id: str | None) -> None:
        with self.sessions() as session:
            if alert_id is None:
                incident = session.get(IncidentTable, incident_id)
                alert_id = incident.alert_id if incident is not None else None
            if alert_id is not None:
                self._registered_alert(session, alert_id)

    def _registered_namespace(self, incident_id: str, alert_id: str) -> str:
        with self.sessions() as session:
            incident = session.get(IncidentTable, incident_id)
            if incident is None or incident.alert_id != alert_id:
                raise DemoRegistrationError("demo incident is outside its registration")
            run_id = self._registered_alert(session, alert_id)
            if run_id is None:
                raise DemoRegistrationError("demo alert is outside its registration")
        return sha256(f"{run_id}:{incident_id}".encode()).hexdigest()[:32]

    def _registered_alert(self, session: Session, alert_id: str) -> str | None:
        match = _ALERT.fullmatch(alert_id)
        if match is None:
            return None
        if self.mode is None:
            raise DemoRegistrationError("请启用 SQL 注入演示配置。")
        run_id, variant = match.groups()
        try:
            registration = json.loads(
                (self.directory / f"{run_id}.json").read_text(encoding="utf-8")
            )
            expected_mode = "deepseek" if variant == "DEEPSEEK" else "fixture"
            if (
                registration["run_id"] != run_id
                or registration["alerts"][alert_id] != expected_mode
            ):
                raise ValueError("invalid registration")
            event_ids = registration["event_ids"]
            hashes = registration["event_hashes"]
            if (
                not isinstance(event_ids, list)
                or not all(isinstance(event_id, str) for event_id in event_ids)
                or not isinstance(hashes, dict)
                or len(event_ids) != 5
                or len(set(event_ids)) != 5
                or set(event_ids) != set(hashes)
            ):
                raise ValueError("invalid event registration")
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise DemoRegistrationError(
                "demo registration is missing or invalid"
            ) from error
        if self.mode != expected_mode:
            raise DemoRegistrationError(
                f"此演示告警需要后端运行在 {expected_mode} 模式。"
            )
        alert = session.get(AlertTable, alert_id)
        if alert is None or alert.event_ids != event_ids:
            raise DemoRegistrationError("demo alert is outside its registration")
        events = session.scalars(
            select(SecurityEventTable).where(SecurityEventTable.event_id.in_(event_ids))
        ).all()
        if len(events) != len(event_ids) or any(
            event.content_sha256 != hashes[event.event_id]
            or calculate_content_sha256(event.raw) != event.content_sha256
            or event.raw.get("dataset_id") != f"sqli-{run_id}"
            or event.raw.get("source_ip") != _TARGET
            for event in events
        ):
            raise DemoRegistrationError("demo evidence differs from its registration")
        return run_id

    @staticmethod
    def _scope(state: dict, action: SimulatedAction) -> dict:
        return {
            "namespace": state["verification_namespace"],
            "incident_id": state["incident_id"],
            "plan_version": state["approved_plan_version"],
            "action_id": action.action_id,
            "source_ip": action.target,
        }

    @staticmethod
    def _event_id(scope: dict, phase: str) -> str:
        return "SE-" + calculate_content_sha256({**scope, "phase": phase})[:48]

    async def apply(self, state: dict, action: SimulatedAction) -> bool:
        if action.action != "block_ip_simulated" or action.target != _TARGET:
            return False
        namespace = await self.authorize(state["incident_id"], state["alerts"])
        if namespace is None or namespace != state["verification_namespace"]:
            return False
        return await asyncio.to_thread(self._apply, self._scope(state, action))

    def _apply(self, scope: dict) -> bool:
        with self.sessions() as session:
            session.execute(
                select(IncidentTable.incident_id)
                .where(IncidentTable.incident_id == scope["incident_id"])
                .with_for_update()
            ).scalar_one()
            phases = ("before", "after")
            event_ids = [self._event_id(scope, phase) for phase in phases]
            existing = [
                session.get(SecurityEventTable, event_id) for event_id in event_ids
            ]
            if any(existing):
                # The after record is the durable overlay for this isolated action.
                return all(existing) and self._read_pair(session, scope) is not None

            blocked: set[str] = set()
            target = scope["source_ip"]
            before = datetime.now(UTC)
            snapshots = [(before, target in blocked)]
            blocked.add(target)
            after = max(datetime.now(UTC), before + timedelta(microseconds=1))
            snapshots.append((after, target in blocked))
            evidence = []
            for phase, event_id, (observed_at, network_blocked) in zip(
                phases, event_ids, snapshots, strict=True
            ):
                raw = {
                    **scope,
                    "phase": phase,
                    "observed_at": observed_at.isoformat(),
                    "network_blocked": network_blocked,
                    "simulation_only": True,
                }
                digest = calculate_content_sha256(raw)
                session.add(
                    SecurityEventTable(
                        event_id=event_id,
                        source=_SOURCE,
                        external_id=event_id,
                        deduplication_key=f"id:{event_id}",
                        observed_at=observed_at,
                        ingested_at=observed_at,
                        severity="info",
                        event_type="simulation.control",
                        raw=raw,
                        content_sha256=digest,
                    )
                )
                evidence.append(
                    EvidenceItem(
                        evidence_id="EV-" + new_ulid(),
                        event_id=event_id,
                        source=_SOURCE,
                        observed_at=observed_at,
                        query={"action_id": scope["action_id"], "phase": phase},
                        summary=f"本地模拟封禁{'前' if phase == 'before' else '后'}的控制状态",
                        content_sha256=digest,
                    )
                )
            session.flush()
            EvidenceRepository(session).add_many(scope["incident_id"], evidence)
            return snapshots[1][1]

    def _read_pair(self, session: Session, scope: dict):
        pair, evidence = {}, []
        for phase in ("before", "after"):
            event_id = self._event_id(scope, phase)
            row = session.execute(
                select(SecurityEventTable, EvidenceItemTable)
                .join(
                    EvidenceItemTable,
                    EvidenceItemTable.event_id == SecurityEventTable.event_id,
                )
                .where(
                    SecurityEventTable.event_id == event_id,
                    EvidenceItemTable.incident_id == scope["incident_id"],
                )
            ).one_or_none()
            if row is None:
                return None
            event, item = row
            raw = event.raw
            if (
                event.source != _SOURCE
                or raw.get("phase") != phase
                or raw.get("simulation_only") is not True
                or any(raw.get(key) != value for key, value in scope.items())
                or calculate_content_sha256(raw) != event.content_sha256
                or item.content_sha256 != event.content_sha256
            ):
                return None
            observation = EffectObservation(
                namespace=scope["namespace"],
                action_id=scope["action_id"],
                target=scope["source_ip"],
                observed_at=raw["observed_at"],
                evidence_ids=[item.evidence_id],
                network_blocked=raw["network_blocked"],
            )
            pair[phase] = observation.model_dump(mode="json")
            model = EvidenceItem.model_validate(item, from_attributes=True)
            evidence.append({**model.model_dump(mode="json"), "raw": raw})
        return pair, evidence

    async def observe(self, state: dict, _run_id: str, result: dict) -> dict:
        if not state.get("verification_namespace"):
            return {}
        namespace = await self.authorize(state["incident_id"], state["alerts"])
        if namespace is None or namespace != state["verification_namespace"]:
            return {}
        return await asyncio.to_thread(self._observe, state, result)

    def _observe(self, state: dict, result: dict) -> dict:
        plan = ResponsePlan.model_validate(state["response_plan"])
        if len(plan.actions) != 1 or len(result["executed_checks"]) != 1:
            return {}
        check = result["executed_checks"][0]
        if not check["evidence_ids"]:
            return {}
        action = SimulatedAction.model_validate(plan.actions[0])
        with self.sessions() as session:
            observed = self._read_pair(session, self._scope(state, action))
        if observed is None:
            return {}
        pair, evidence = observed
        return {
            "effect_observations": {check["check_id"]: pair},
            "evidence": [*result["evidence"], *evidence],
        }
