from pathlib import Path

import pytest

from evidencesoc.agents.capabilities import InvestigationCapabilities, capability_scope
from evidencesoc.config import Settings
from evidencesoc.mcp_server.client import build_stdio_parameters
from evidencesoc.mcp_server.context import RunContext
from evidencesoc.tools.attack_work import AttackKnowledgeRepository


def test_mcp_child_gets_effective_rag_policy_and_allowed_tools():
    policy = InvestigationCapabilities(allowed_tools=frozenset({'search_security_events', 'get_alert_context'}), rag_mode='disabled')
    with capability_scope(policy):
        params = build_stdio_parameters(RunContext('r','i','t'), settings=Settings(_env_file=None), backend_dir=Path('.'))
    assert params.env['EVIDENCESOC_RAG_MODE'] == 'disabled'
    assert 'lookup_attack_technique' not in params.env['EVIDENCESOC_ALLOWED_TOOLS']


@pytest.mark.parametrize('mode', ['disabled','semantic_only'])
def test_legacy_keyword_repository_cannot_bypass_policy(mode):
    class Session:
        def execute(self, *args):
            pytest.fail('legacy SQL must never run under this policy')
    with capability_scope(InvestigationCapabilities(rag_mode=mode)):
        with pytest.raises(PermissionError):
            AttackKnowledgeRepository(Session()).lookup(query='T1059',limit=5)
