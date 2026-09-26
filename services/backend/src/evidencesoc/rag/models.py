from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EmbeddingProvider(Protocol):
    @property
    def model_id(self) -> str: ...

    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...


class SourceManifest(BaseModel):
    """Operator-supplied, verified provenance for the exact raw input bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1, max_length=128)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    downloaded_at: datetime
    source_uri: str = Field(min_length=1, max_length=2048)

    @field_validator("downloaded_at")
    @classmethod
    def aware_date(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("downloaded_at must be timezone-aware")
        return value


class KnowledgeChunk(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    knowledge_chunk_id: str = Field(pattern=r"^KC-[0-9a-f]{60}$")
    source_uri: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1)
    content: str = Field(min_length=1, max_length=1500)
    technique_id: str | None = Field(default=None, pattern=r"^T\d{4}(?:\.\d{3})?$")
    object_type: Literal["attack-pattern", "manual"]
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    body_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    downloaded_at: datetime
    embedding_model: str = Field(min_length=1, max_length=255)
    stix_id: str | None = None
    trusted: bool = False

    @property
    def metadata(self) -> dict[str, Any]:
        values = self.model_dump(mode="json", exclude={"knowledge_chunk_id", "content"})
        values.update(revoked=False, deprecated=False)
        if self.object_type == "attack-pattern":
            values.update(stix_hash=self.source_hash, source_type="mitre_attack")
        else:
            values["source_type"] = "internal_manual"
        return values
