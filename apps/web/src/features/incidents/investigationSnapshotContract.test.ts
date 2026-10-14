import { afterEach, expect, it, vi } from 'vitest';
import { investigationSnapshotSchema, loadInvestigationSnapshot } from './investigationSnapshotContract';

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

const snapshot = {
  investigation_id: 'IV-1', incident_id: 'IN-1', alert_id: 'AL-1', status: 'collecting',
  created_at: '2026-09-29T01:00:00Z', trace_id: 'TRACE-1',
  alerts: [{ alert_id: 'AL-1', title: '可疑请求', severity: 'high' }],
  evidence: [], attack_steps: [], runs: [], origin: null, classification: null,
  response_plan: null, validation_result: null, fallback_used: false, stop_reason: null,
  revision: '3', stream_cursor: '2', updated_at: '2026-09-29T01:00:01Z',
  mode: 'rules', available_actions: [],
  attack_graph: { revision: '3', generated_at: '2026-09-29T01:00:01Z', nodes: [], edges: [] },
} as const;

it('调查快照保留同一视图的修订版与游标，并拒绝错误编号或非法版本', async () => {
  expect(investigationSnapshotSchema.parse(snapshot).stream_cursor).toBe('2');
  expect(investigationSnapshotSchema.parse(snapshot).attack_graph.edges).toEqual([]);
  expect(investigationSnapshotSchema.safeParse({ ...snapshot, revision: '3.5' }).success).toBe(false);
  expect(investigationSnapshotSchema.safeParse({ ...snapshot, attack_graph: {
    ...snapshot.attack_graph, edges: [{ edge_id: 'EDGE-1', source_step_id: 'STEP-missing',
      target_step_id: 'STEP-other', relation: 'follows', description: null,
      confidence: null, evidence_ids: [], support_status: 'candidate' }],
  } }).success).toBe(false);
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(snapshot)));
  vi.stubGlobal('fetch', fetcher);
  expect(await loadInvestigationSnapshot('IV-1')).toMatchObject({ revision: '3', stream_cursor: '2' });
  expect(String(fetcher.mock.calls[0][0])).toBe('/api/v1/investigations/IV-1');
  await expect(loadInvestigationSnapshot('IV-escape')).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
});
