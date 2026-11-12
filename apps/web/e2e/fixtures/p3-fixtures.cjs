'use strict';
// Synthetic, read-only P3 acceptance fixtures. Never imported into application bundles.
// Stored hashes are illustrative schema-compatible values, NOT computed/verified hashes.
// eslint-disable-next-line @typescript-eslint/no-require-imports -- CommonJS fixture loaded by Playwright
const p2 = require('./p2-fixtures.cjs');
const incidentId = 'IN-P3-ORBIT';
const investigationId = 'IV-P3-ORBIT';
const updatedAt = '2026-11-04T03:30:00Z';
const stepIds = ['STEP-P3-1', 'STEP-P3-2', 'STEP-P3-3', 'STEP-P3-4'];
const evidenceIds = ['EV-P3-ENTRY', 'EV-P3-EXEC', 'EV-P3-CREDENTIAL'];
const evidence = [
  { evidence_id: evidenceIds[0], event_id: 'EVENT-P3-1', source: 'nginx',
    observed_at: '2026-11-04T03:20:00Z', query: { filters: { event_id: 'EVENT-P3-1' } },
    summary: '[P3合成] 入口请求日志', content_sha256: 'a'.repeat(64) },
  { evidence_id: evidenceIds[1], event_id: 'EVENT-P3-2', source: 'sysmon',
    observed_at: '2026-11-04T03:21:00Z', query: { filters: { event_id: 'EVENT-P3-2' } },
    summary: '[P3合成] 进程执行记录', content_sha256: 'b'.repeat(64) },
  { evidence_id: evidenceIds[2], event_id: 'EVENT-P3-3', source: 'Windows Security',
    observed_at: '2026-11-04T03:23:00Z', query: { filters: { event_id: 'EVENT-P3-3' } },
    summary: '[P3合成] 凭据访问线索', content_sha256: 'c'.repeat(64) },
];
const attackSteps = [
  { attack_step_id: stepIds[0], incident_id: incidentId, sequence: 1, phase: 'initial_access',
    technique_id: 'T1190', description: '异常入口请求', occurred_at: evidence[0].observed_at, evidence_ids: [evidenceIds[0]] },
  { attack_step_id: stepIds[1], incident_id: incidentId, sequence: 2, phase: 'execution',
    technique_id: 'T1059', description: '命令执行轨迹', occurred_at: evidence[1].observed_at, evidence_ids: [evidenceIds[1]] },
  { attack_step_id: stepIds[2], incident_id: incidentId, sequence: 3, phase: 'credential_access',
    technique_id: 'T1003', description: '凭据访问候选', occurred_at: evidence[2].observed_at, evidence_ids: [evidenceIds[2]] },
  { attack_step_id: stepIds[3], incident_id: incidentId, sequence: 4, phase: 'collection',
    technique_id: null, description: '目录访问待核实', occurred_at: '2026-11-04T03:25:00Z', evidence_ids: [] },
];
const incident = {
  incident_id: incidentId, alert_id: 'AL-P3-SYNTHETIC', status: 'completed',
  created_at: evidence[0].observed_at, investigation_id: investigationId, trace_id: 'TRACE-P3-SYNTHETIC',
  alerts: [{ alert_id: 'AL-P3-SYNTHETIC', title: '[P3合成样例] 异常请求与执行线索', severity: 'high',
    created_at: evidence[0].observed_at, event_ids: evidence.map((item) => item.event_id) }],
  evidence, knowledge: [], attack_steps: attackSteps,
  runs: ['triage', 'collect', 'analyze', 'reconstruct', 'respond', 'validate'].map((agent_name, index) => ({
    run_id: `RUN-P3-${index + 1}`, incident_id: incidentId, agent_name, status: 'completed',
    started_at: new Date(Date.parse('2026-11-04T03:26:00Z') + index * 30000).toISOString(),
    finished_at: new Date(Date.parse('2026-11-04T03:26:20Z') + index * 30000).toISOString(),
    evidence_ids: index === 1 ? evidenceIds : [],
  })),
  origin: { observed_source_ip: '198.51.100.42', entry_host: 'edge-origin-only', entry_service: 'gateway',
    first_seen_at: evidence[0].observed_at, source_scope: 'external', confidence: 0.71, evidence_ids: [evidenceIds[0]] },
  classification: { primary_type: 'synthetic_visual_fixture', attack_types: ['synthetic_visual_fixture'],
    attack_phase: 'collection', technique_ids: ['T1190', 'T1059', 'T1003'], confidence: 0.71, evidence_ids: [...evidenceIds] },
  response_plan: null, approval: null,
  validation_result: { outcome: 'insufficient_evidence', summary: '合成验收样例；不代表真实响应或攻击结论。', checked_at: updatedAt },
  simulation: [], fallback_used: false, errors: [], stop_reason: 'P3_SYNTHETIC_COMPLETE',
};
const snapshot = {
  ...incident, revision: '20', stream_cursor: '19', updated_at: updatedAt, mode: 'rules', available_actions: [],
  attack_graph: {
    revision: '20', generated_at: updatedAt,
    nodes: attackSteps.map((step, index) => ({ step_id: step.attack_step_id, sequence: step.sequence,
      phase: step.phase, description: step.description, host: ['app-01', 'app-01', 'auth-01', 'files-01'][index],
      service: ['nginx', 'shell', 'lsass', 'smb'][index], observed_at: step.occurred_at,
      technique_ids: step.technique_id ? [step.technique_id] : [], confidence: [0.93, 0.82, 0.47, null][index],
      evidence_ids: step.evidence_ids, support_status: ['supported', 'supported', 'candidate', 'insufficient'][index],
    })),
    edges: [
      { edge_id: 'EDGE-P3-TEMPORAL', source_step_id: stepIds[0], target_step_id: stepIds[1], relation: 'temporal',
        description: '合成时间先后，不声明因果。', confidence: null, evidence_ids: [evidenceIds[0], evidenceIds[1]], support_status: 'supported' },
      { edge_id: 'EDGE-P3-CANDIDATE', source_step_id: stepIds[1], target_step_id: stepIds[2], relation: 'causal_candidate',
        description: '合成因果候选，仍需核实。', confidence: 0.47, evidence_ids: [evidenceIds[1], evidenceIds[2]], support_status: 'candidate' },
      { edge_id: 'EDGE-P3-RELATED', source_step_id: stepIds[2], target_step_id: stepIds[3], relation: 'related',
        description: '合成行为关联，无方向且证据不足。', confidence: null, evidence_ids: [], support_status: 'insufficient' },
    ],
  },
};
const noRelationships = { ...snapshot, revision: '21', attack_graph: { ...snapshot.attack_graph, revision: '21', edges: [] } };
const missingMetadata = {
  ...noRelationships, revision: '22',
  attack_steps: attackSteps.map((step, index) => index === 2 ? { ...step, phase: null, technique_id: null } : step),
  attack_graph: { ...noRelationships.attack_graph, revision: '22',
    nodes: snapshot.attack_graph.nodes.map((node, index) => index === 2 ? {
      ...node, phase: null, host: null, service: null, technique_ids: [], confidence: null,
    } : node),
  },
};
const evidenceDetails = Object.fromEntries(evidence.map((item, index) => [item.evidence_id, {
  evidence: { ...item, incident_id: incidentId }, raw_access: 'full',
  raw_event: { event_id: item.event_id, source: item.source, observed_at: item.observed_at,
    severity: 'high', event_type: 'synthetic_p3_visual_fixture', content_sha256: item.content_sha256,
    raw: { synthetic: true, note: 'P3 visual fixture; not a production event.', event_id: item.event_id,
      host: ['app-01', 'app-01', 'auth-01'][index], action: ['request_observed', 'process_created', 'credential_candidate'][index] } },
  integrity: { algorithm: 'sha256', canonicalization: 'evidencesoc-json-v1', scope: 'postgresql',
    status: 'unavailable', checked_at: updatedAt, calculated_sha256: null,
    stored_event_sha256: item.content_sha256, stored_evidence_sha256: item.content_sha256 },
}]));
function evidencePage(page = 1, pageSize = 20) {
  return { items: evidence.slice((page - 1) * pageSize, page * pageSize).map((item) => ({ ...item, incident_id: incidentId })),
    total: evidence.length, page, page_size: pageSize };
}
const session = { actor_id: 'demo-reviewer', role: 'reviewer', allowed_actions: [], expires_at: '2030-01-01T00:00:00Z' };
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
module.exports = deepFreeze({ incidentId, investigationId, stepIds, evidenceIds, incident, snapshot,
  noRelationships, missingMetadata, evidenceDetails, evidencePage, session, health: structuredClone(p2.health), summary: p2.summary });
