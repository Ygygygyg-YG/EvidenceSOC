from __future__ import annotations

from sqlalchemy import delete

from evidencesoc.config import Settings
from evidencesoc.ids import new_ulid
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.tables import KnowledgeChunkTable
from evidencesoc.tools.attack_work import AttackKnowledgeRepository


def test_attack_lookup_runs_against_postgresql_jsonb() -> None:
    prefix = f"KC-task6-{new_ulid()}"
    keyword_query = f"task6publicfacing{new_ulid()}"
    chunk_ids = {
        kind: f"{prefix}-{kind}"
        for kind in (
            "active",
            "revoked",
            "deprecated",
            "manual",
            "untrusted",
            "mismatched",
            "bad-id",
        )
    }
    settings = Settings()
    engine = create_database_engine(settings.database_url)
    sessions = create_session_factory(engine)
    try:
        with sessions() as session:
            try:
                session.add_all(
                    [
                        KnowledgeChunkTable(
                            knowledge_chunk_id=chunk_ids["active"],
                            source="https://attack.mitre.org/techniques/T1190/",
                            content=f"{keyword_query}: Exploit a public-facing application.",
                            chunk_metadata={
                                "object_type": "attack-pattern",
                                "technique_id": "T1190",
                                "title": "Exploit Public-Facing Application",
                                "version": "19.2",
                            },
                        ),
                        KnowledgeChunkTable(
                            knowledge_chunk_id=chunk_ids["revoked"],
                            source="https://attack.mitre.org/techniques/T1190/",
                            content=f"{keyword_query}: revoked",
                            chunk_metadata={
                                "object_type": "attack-pattern",
                                "technique_id": "T1190",
                                "title": "Revoked technique",
                                "version": "19.2",
                                "revoked": True,
                            },
                        ),
                        KnowledgeChunkTable(
                            knowledge_chunk_id=chunk_ids["deprecated"],
                            source="https://attack.mitre.org/techniques/T1190/",
                            content=f"{keyword_query}: deprecated",
                            chunk_metadata={
                                "object_type": "attack-pattern",
                                "technique_id": "T1190",
                                "title": "Deprecated technique",
                                "version": "19.2",
                                "deprecated": True,
                            },
                        ),
                        KnowledgeChunkTable(
                            knowledge_chunk_id=chunk_ids["manual"],
                            source="https://attack.mitre.org/techniques/T1190/",
                            content=f"{keyword_query}: A public-facing internal manual.",
                            chunk_metadata={
                                "object_type": "manual",
                                "technique_id": "T1190",
                                "title": "Internal public-facing note",
                                "version": "19.2",
                            },
                        ),
                        KnowledgeChunkTable(
                            knowledge_chunk_id=chunk_ids["untrusted"],
                            source="https://example.invalid/techniques/T1190/",
                            content=f"{keyword_query}: Untrusted public-facing technique text.",
                            chunk_metadata={
                                "object_type": "attack-pattern",
                                "technique_id": "T1190",
                                "title": "Untrusted public-facing claim",
                                "version": "19.2",
                            },
                        ),
                        KnowledgeChunkTable(
                            knowledge_chunk_id=chunk_ids["mismatched"],
                            source="https://attack.mitre.org/techniques/T1059/",
                            content=f"{keyword_query}: Mismatched public-facing source.",
                            chunk_metadata={
                                "object_type": "attack-pattern",
                                "technique_id": "T1190",
                                "title": "Mismatched public-facing technique",
                                "version": "19.2",
                            },
                        ),
                        KnowledgeChunkTable(
                            knowledge_chunk_id=chunk_ids["bad-id"],
                            source="https://attack.mitre.org/techniques/T1190/",
                            content=f"{keyword_query}: Malformed public-facing technique ID.",
                            chunk_metadata={
                                "object_type": "attack-pattern",
                                "technique_id": "T11X0",
                                "title": "Malformed public-facing technique",
                                "version": "19.2",
                            },
                        ),
                    ]
                )
                session.commit()
                repository = AttackKnowledgeRepository(session)
                exact = repository.lookup(query="t1190", limit=10)
                exact_ids = {item["knowledge_chunk_id"] for item in exact}
                assert chunk_ids["active"] in exact_ids
                assert not exact_ids.intersection(
                    {
                        chunk_id
                        for kind, chunk_id in chunk_ids.items()
                        if kind != "active"
                    }
                )
                assert all(item["technique_id"] == "T1190" for item in exact)
                keyword = repository.lookup(query=keyword_query, limit=10)
                assert [item["knowledge_chunk_id"] for item in keyword] == [
                    chunk_ids["active"]
                ]
                # The full ATT&CK corpus contains literal percent/underscore
                # characters. Verify escaping rather than assuming an empty DB.
                for literal in ("%", "_"):
                    matches = repository.lookup(query=literal, limit=10)
                    assert all(
                        any(
                            literal in item[field]
                            for field in ("technique_id", "title", "summary")
                        )
                        for item in matches
                    )
                assert repository.lookup(query="T9999", limit=10) == []
            finally:
                session.rollback()
                session.execute(
                    delete(KnowledgeChunkTable).where(
                        KnowledgeChunkTable.knowledge_chunk_id.in_(chunk_ids.values())
                    )
                )
                session.commit()
    finally:
        engine.dispose()
