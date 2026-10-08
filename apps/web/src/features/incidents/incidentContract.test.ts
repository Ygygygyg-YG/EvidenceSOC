import { describe, expect, it } from 'vitest';
import { incidentSummarySchema } from './incidentContract';

describe('incident workbench contract', () => {
  const incident = {
    incident_id: 'IN-1', alert_id: 'AL-1', status: 'awaiting_approval',
    created_at: '2026-09-21T10:20:24Z', investigation_id: 'IV-1', trace_id: null,
    alerts: [], evidence: [{ evidence_id: 'EV-01K5TESTTESTTESTTESTTESTTEST', event_id: 'EVT-1',
      source: 'nginx', observed_at: '2026-09-21T10:20:24Z', query: { filters: { event_id: 'EVT-1' } },
      summary: '真实日志摘要', content_sha256: 'a'.repeat(64) }],
    attack_steps: [{ attack_step_id: 'STEP-1', sequence: 1, phase: 'initial_access',
      technique_id: 'T1190', description: '尝试访问', occurred_at: '2026-09-21T10:20:24Z',
      evidence_ids: ['EV-01K5TESTTESTTESTTESTTESTTEST'], incident_id: 'IN-1' }],
    runs: [{ run_id: 'RUN-1', incident_id: 'IN-1', agent_name: 'triage', status: 'completed',
      started_at: '2026-09-21T10:20:24Z', finished_at: '2026-09-21T10:21:24Z', evidence_ids: [] }],
    origin: null, classification: null, response_plan: null, validation_result: null,
    fallback_used: false, stop_reason: null,
  };

  it('retains evidence query, hash, step references and real run times', () => {
    const parsed = incidentSummarySchema.parse(incident);
    expect(parsed.evidence[0].query).toEqual({ filters: { event_id: 'EVT-1' } });
    expect(parsed.evidence[0].content_sha256).toBe('a'.repeat(64));
    expect(parsed.attack_steps[0].evidence_ids).toEqual(['EV-01K5TESTTESTTESTTESTTESTTEST']);
    expect(parsed.runs[0].finished_at).toBe('2026-09-21T10:21:24Z');
  });

  it('rejects a malformed evidence hash instead of presenting it as valid', () => {
    const malformed = { ...incident, evidence: [{ ...incident.evidence[0], content_sha256: 'bad' }] };
    expect(incidentSummarySchema.safeParse(malformed).success).toBe(false);
  });
});
