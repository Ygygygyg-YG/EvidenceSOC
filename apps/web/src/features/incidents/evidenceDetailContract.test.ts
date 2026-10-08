import { describe, expect, it } from 'vitest';
import { evidenceDetailSchema } from './evidenceDetailContract';

const response = {
  evidence: { evidence_id: 'EV-01K5TESTTESTTESTTESTTESTTESU', incident_id: 'IN-1', event_id: 'EVT-2', source: 'waf',
    observed_at: '2026-09-21T10:21:24Z', query: { filters: { event_id: 'EVT-2' } },
    summary: '规则命中记录', content_sha256: 'b'.repeat(64) },
  raw_event: { event_id: 'EVT-2', source: 'waf', observed_at: '2026-09-21T10:21:24Z',
    severity: 'high', event_type: 'waf_alert', raw: { request_path: '/login', rule: 'sqli' },
    content_sha256: 'b'.repeat(64) },
  raw_access: 'full',
  integrity: { algorithm: 'sha256', canonicalization: 'evidencesoc-json-v1', scope: 'postgresql',
    status: 'verified', checked_at: '2026-09-21T10:22:24Z', calculated_sha256: 'b'.repeat(64),
    stored_event_sha256: 'b'.repeat(64), stored_evidence_sha256: 'b'.repeat(64) },
};

describe('authorized evidence detail contract', () => {
  it('keeps raw event and scoped server integrity result', () => {
    const parsed = evidenceDetailSchema.parse(response);
    expect(parsed.raw_event.raw).toEqual({ request_path: '/login', rule: 'sqli' });
    expect(parsed.integrity).toMatchObject({ scope: 'postgresql', status: 'verified' });
  });

  it('never accepts a fabricated unscoped verification status', () => {
    expect(evidenceDetailSchema.safeParse({ ...response,
      integrity: { ...response.integrity, scope: 'all-sources', status: 'verified' },
    }).success).toBe(false);
  });

  it('accepts an unavailable verification only with no calculated hash', () => {
    const parsed = evidenceDetailSchema.parse({ ...response, integrity: {
      ...response.integrity, status: 'unavailable', calculated_sha256: null,
    } });
    expect(parsed.integrity.calculated_sha256).toBeNull();
  });
});
