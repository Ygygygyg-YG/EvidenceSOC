from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel
from pydantic.json_schema import JsonSchemaMode, models_json_schema

from evidencesoc.domain.models import (
    AgentRun,
    Alert,
    ApprovalRecord,
    AttackClassification,
    AttackOrigin,
    EvidenceItem,
    Incident,
    ResponsePlan,
    SecurityEvent,
    ValidationResult,
)

DOMAIN_MODELS: tuple[type[BaseModel], ...] = (
    SecurityEvent,
    Alert,
    Incident,
    EvidenceItem,
    AttackOrigin,
    AttackClassification,
    AgentRun,
    ResponsePlan,
    ApprovalRecord,
    ValidationResult,
)


class EvidenceSOCApp(FastAPI):
    def openapi(self) -> dict[str, Any]:
        if self.openapi_schema is not None:
            return self.openapi_schema

        schema = get_openapi(
            title=self.title,
            version=self.version,
            openapi_version=self.openapi_version,
            summary=self.summary,
            description=self.description,
            routes=self.routes,
        )

        model_inputs: list[
            tuple[type[BaseModel], JsonSchemaMode]
        ] = [
            (model, "validation")
            for model in DOMAIN_MODELS
        ]

        _, bundled_schema = models_json_schema(
            model_inputs,
            ref_template="#/components/schemas/{model}",
        )

        definitions = bundled_schema.get("$defs", {})

        components = schema.setdefault("components", {})
        schemas = components.setdefault("schemas", {})
        schemas.update(definitions)

        self.openapi_schema = schema
        return schema
