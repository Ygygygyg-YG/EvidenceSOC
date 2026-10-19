"""Real local services, synthetic logs; never uses labels or calls a model."""
import json
import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from evals.adapters.environment import case_environment
from evals.adapters.seed import load_seed
from evals.contracts import WorkerRunSpec


def test_original_checkpoint_resources_can_survive_for_actual_human_approval(tmp_path,monkeypatch):
    from evidencesoc.config import Settings
    from evidencesoc.persistence.event_search import create_opensearch_client
    configured=Settings()  # explicit control-side local service configuration
    monkeypatch.setenv('DATABASE_URL',configured.database_url)
    monkeypatch.setenv('OPENSEARCH_URL',configured.opensearch_url)
    source=tmp_path/'agent'
    source.mkdir()
    event={'source':'fixture','severity':'info','event_type':'observation','host':'synthetic-host',
           'observed_at':'2026-10-18T00:00:00Z','message':'synthetic service test only'}
    (source/'events.jsonl').write_text(json.dumps(event)+'\n',encoding='utf-8')
    knowledge=tmp_path/'knowledge'
    knowledge.mkdir()
    (knowledge/'knowledge_chunks.jsonl').write_text(json.dumps({'knowledge_chunk_id':'synthetic-test',
        'source':'https://example.test/public','content':'Synthetic test only',
        'chunk_metadata':{'version':'test'},'embedding':None})+'\n',encoding='utf-8')
    monkeypatch.setenv('RAG_DATA_DIRECTORY',str(knowledge))
    settings=Settings(_env_file=None)
    spec=WorkerRunSpec(run_id='synthetic-services',case_id='case1',group='B3',config_sha256='a'*64)
    seed=load_seed(spec,source)
    reference=None
    try:
        with case_environment(spec,seed) as environment:
            case_settings,sessions,incident_id=environment
            with sessions() as session:
                assert session.execute(text('select count(*) from security_events')).scalar_one()==1
            reference=environment.retain()
            assert reference['database_name'].startswith('task13_')
            assert reference['incident_id']==incident_id
        engine=create_engine(make_url(settings.database_url).set(database=reference['database_name']))
        try:
            with engine.connect() as connection:
                assert connection.execute(text('select count(*) from incidents')).scalar_one()==1
        finally:
            engine.dispose()
    finally:
        if reference:
            # Names came from this test's actual resource handle, never discovery.
            admin=create_engine(make_url(settings.database_url).set(database='postgres'),isolation_level='AUTOCOMMIT')
            try:
                with admin.connect() as connection:
                    connection.exec_driver_sql(f'DROP DATABASE "{reference["database_name"]}" WITH (FORCE)')
            finally:
                admin.dispose()
            search=create_opensearch_client(settings.opensearch_url)
            try:
                search.indices.delete(index=reference['index_name'])
            finally:
                search.close()


def test_knowledge_snapshot_is_exact_pinned_public_corpus_not_unreviewed_manuals(tmp_path):
    from evidencesoc.config import Settings
    from evals.adapters.environment import export_knowledge
    snapshot=tmp_path/'knowledge_chunks.jsonl'
    receipt=export_knowledge(Settings(),snapshot)
    rows=[json.loads(line) for line in snapshot.read_text(encoding='utf-8').splitlines()]
    assert receipt['rows']==997
    assert len(rows)==997
    assert all(row['chunk_metadata']['version']=='19.2' and row['chunk_metadata']['object_type']=='attack-pattern' for row in rows)
