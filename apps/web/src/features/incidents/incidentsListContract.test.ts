import { afterEach, expect, it, vi } from 'vitest';
import { buildIncidentsQuery, incidentDetailHref, incidentListReturnHref, incidentPageSchema, loadIncidents, readIncidentFilters } from './incidentsListContract';

const record = {
  incident_id: 'IN-test', investigation_id: 'IV-test', alert_id: 'AL-test',
  alert_title: 'SQL 注入演示告警', severity: 'high', status: 'awaiting_approval',
  created_at: '2026-09-30T02:00:00Z', evidence_count: 10, validation_outcome: null,
};

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it('只接受真实案件列表字段，保留 total 与案件状态', () => {
  const page = { items: [record], total: 1, page: 1, page_size: 20 };
  expect(incidentPageSchema.parse(page)).toEqual(page);
  expect(incidentPageSchema.safeParse({ ...page, items: [{ ...record, evidence_count: -1 }] }).success).toBe(false);
  expect(incidentPageSchema.safeParse({ ...page, total: 0 }).success).toBe(false);
  expect(incidentPageSchema.safeParse({ ...page, items: [{ ...record, validation_outcome: 'unknown' }] }).success).toBe(false);
});

it('URL 恢复页码和状态，非法筛选回到默认值', () => {
  expect(readIncidentFilters(new URLSearchParams('page=3&page_size=50&status=awaiting_approval')))
    .toEqual({ page: 3, pageSize: 50, status: 'awaiting_approval', risk: undefined, timeFrom: undefined, timeTo: undefined });
  expect(readIncidentFilters(new URLSearchParams('page=-1&page_size=500&status=bogus')))
    .toEqual({ page: 1, pageSize: 20, status: undefined, risk: undefined, timeFrom: undefined, timeTo: undefined });
  expect(buildIncidentsQuery({ page: 2, pageSize: 20, status: 'failed' })).toBe('page=2&page_size=20&status=failed');
});

it('URL 恢复高危及有效时间范围，拒绝缺失或倒置时间', () => {
  const query = 'page=2&page_size=50&risk=high&status=completed&time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z';
  const filters = readIncidentFilters(new URLSearchParams(query));
  expect(filters).toEqual({ page: 2, pageSize: 50, status: 'completed', risk: 'high',
    timeFrom: '2026-09-30T00:00:00Z', timeTo: '2026-10-01T00:00:00Z' });
  expect(buildIncidentsQuery(filters)).toBe('page=2&page_size=50&status=completed&risk=high&time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
  expect(readIncidentFilters(new URLSearchParams('risk=low&time_from=2026-09-30T00:00:00Z'))).toMatchObject({ risk: undefined, timeFrom: undefined, timeTo: undefined });
  expect(readIncidentFilters(new URLSearchParams('time_from=2026-10-01T00:00:00Z&time_to=2026-09-30T00:00:00Z'))).toMatchObject({ timeFrom: undefined, timeTo: undefined });
});

it('案件详情返回原始调查列表筛选，且不接受外部重定向', () => {
  const filters = readIncidentFilters(new URLSearchParams('page=2&status=completed&risk=high&time_from=2026-09-30T00:00:00Z&time_to=2026-10-01T00:00:00Z'));
  const detail = incidentDetailHref('IN-1', filters);
  const from = new URL(detail, 'http://web.test').searchParams.get('from');
  expect(incidentListReturnHref(from)).toBe(`/incidents?${buildIncidentsQuery(filters)}`);
  expect(incidentListReturnHref('https://evil.test/path')).toBe('/incidents?page=1&page_size=20');
  expect(incidentListReturnHref(null)).toBe('/alerts');
});

it('读取同源分页接口，失败保留后端 code 和 trace', async () => {
  const fetchMock = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ items: [record], total: 1, page: 1, page_size: 20 }), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'DEPENDENCY_UNAVAILABLE', message: '数据库不可用', trace_id: 'TRACE-list' } }), { status: 503 }));
  vi.stubGlobal('fetch', fetchMock);
  await expect(loadIncidents({ page: 1, pageSize: 20 })).resolves.toMatchObject({ total: 1 });
  expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/incidents?page=1&page_size=20');
  await expect(loadIncidents({ page: 1, pageSize: 20 })).rejects.toMatchObject({ code: 'DEPENDENCY_UNAVAILABLE', traceId: 'TRACE-list' });
});

it('调查列表请求携带高危及时间范围', async () => {
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 20 }), { status: 200 }));
  vi.stubGlobal('fetch', fetchMock);
  await loadIncidents({ page: 1, pageSize: 20, risk: 'high', timeFrom: '2026-09-30T00:00:00Z', timeTo: '2026-10-01T00:00:00Z' });
  expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/incidents?page=1&page_size=20&risk=high&time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
});

it('响应页码与请求不一致时拒绝作为成功数据', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [record], total: 1, page: 2, page_size: 20 }), { status: 200 })));
  await expect(loadIncidents({ page: 1, pageSize: 20 })).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
});
