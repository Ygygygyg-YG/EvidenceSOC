import { afterEach, expect, it, vi } from 'vitest';
import { evidencePageSchema, loadEvidencePage } from './evidencePageContract';

const item = {
  evidence_id: 'EV-1', incident_id: 'IN-1', event_id: 'SE-1', source: 'firewall',
  observed_at: '2026-09-29T02:00:00Z', query: { event_id: 'SE-1' },
  summary: '发现异常流量', content_sha256: 'a'.repeat(64),
};

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it('分页只接受有限、有序且无重复的证据摘要', () => {
  const page = { items: [item], total: 2, page: 1, page_size: 1 };
  expect(evidencePageSchema.parse(page).items[0].evidence_id).toBe('EV-1');
  expect(evidencePageSchema.safeParse({ ...page, items: [item, item] }).success).toBe(false);
  expect(evidencePageSchema.safeParse({ ...page, total: 0 }).success).toBe(false);
});

it('按案件与页码读取服务端证据，不接受跨案件或错误页码', async () => {
  const mockedFetch = vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({ items: [item], total: 1, page: 2, page_size: 20 })))
    .mockResolvedValueOnce(new Response(JSON.stringify({ items: [{ ...item, incident_id: 'IN-other' }], total: 1, page: 1, page_size: 20 })));
  vi.stubGlobal('fetch', mockedFetch);
  await expect(loadEvidencePage('IN-1', 1, 20)).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  await expect(loadEvidencePage('IN-1', 1, 20)).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  expect(mockedFetch.mock.calls[0][0]).toBe('/api/v1/incidents/IN-1/evidence?page=1&page_size=20');
});

it('错误响应保留服务端状态与 Trace ID', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
    error: { code: 'INCIDENT_NOT_FOUND', message: '案件不存在', trace_id: 'TRACE-404' },
  }), { status: 404 })));
  await expect(loadEvidencePage('IN-1', 1, 20)).rejects.toMatchObject({
    code: 'INCIDENT_NOT_FOUND', status: 404, traceId: 'TRACE-404',
  });
});
