import { afterEach, expect, it, vi } from 'vitest';
import { alertDetailSchema, loadAlertDetail, startInvestigation } from './alertDetailContract';

const detail = {
  alert_id: 'AL-123', title: 'SQL 注入告警', severity: 'high', created_at: '2026-09-21T10:20:24Z',
  event_ids: ['EV-1'], status: 'received', incident_id: null, investigation_id: null, execution_mode: 'rules',
  events: [{ event_id: 'EV-1', source: 'application', observed_at: '2026-09-21T10:20:20Z', severity: 'high', event_type: 'http_request' }],
};

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it('单告警详情必须包含真实日志摘要且关联 ID 一致', () => {
  expect(alertDetailSchema.parse(detail).events[0].event_id).toBe('EV-1');
  expect(alertDetailSchema.safeParse({ ...detail, events: [] }).success).toBe(false);
  expect(alertDetailSchema.safeParse({ ...detail, events: [{ ...detail.events[0], event_id: 'EV-other' }] }).success).toBe(false);
  expect(alertDetailSchema.safeParse({ ...detail, execution_mode: 'unknown' }).success).toBe(false);
  expect(alertDetailSchema.safeParse({ ...detail, execution_mode: undefined }).success).toBe(false);
});

it('后端允许的点号与冒号编号可用于告警详情及事件摘要', () => {
  expect(alertDetailSchema.safeParse({
    ...detail, alert_id: 'AL.customer:123', event_ids: ['SE.123'],
    events: [{ ...detail.events[0], event_id: 'SE.123' }],
  }).success).toBe(true);
});

it('读取固定同源 URL，并拒绝与 URL 不一致的告警响应', async () => {
  const fetchMock = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify(detail), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ ...detail, alert_id: 'AL-other' }), { status: 200 }));
  vi.stubGlobal('fetch', fetchMock);
  await expect(loadAlertDetail('AL-123')).resolves.toMatchObject({ alert_id: 'AL-123' });
  expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/alerts/AL-123');
  await expect(loadAlertDetail('AL-123')).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
});

it('详情 404 与 trace 可供页面显示，不伪造空告警', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
    error: { code: 'NOT_FOUND', message: 'Requested resource was not found.', trace_id: 'TRACE-detail-404' },
  }), { status: 404, headers: { 'x-trace-id': 'TRACE-detail-404' } })));
  await expect(loadAlertDetail('AL-missing')).rejects.toMatchObject({ code: 'NOT_FOUND', status: 404, traceId: 'TRACE-detail-404' });
});

  it('启动调查发送 alert_id、明确模式和幂等键，并接受后端真实 incident_id', async () => {
  const accepted = { investigation_id: 'INV-123', incident_id: 'IN-123', trace_id: 'TRACE-123', status: 'collecting', stream_url: '/api/v1/investigations/INV-123/stream' };
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(accepted), { status: 202 }));
  vi.stubGlobal('fetch', fetchMock);
  await expect(startInvestigation('AL-123', 'rules', 'start-123')).resolves.toMatchObject({ incident_id: 'IN-123', investigation_id: 'INV-123' });
  expect(fetchMock).toHaveBeenCalledWith('/api/v1/investigations', expect.objectContaining({
    method: 'POST', body: '{"alert_id":"AL-123","mode":"rules"}', cache: 'no-store',
  }));
  expect(new Headers(fetchMock.mock.calls[0][1].headers).get('Idempotency-Key')).toBe('start-123');
});

it('带点号的合法告警编号可启动调查', async () => {
  const accepted = { investigation_id: 'IV-123', incident_id: 'IN-123', trace_id: 'TRACE-123', status: 'received', stream_url: '/api/v1/investigations/IV-123/stream' };
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(accepted), { status: 200 }));
  vi.stubGlobal('fetch', fetchMock);
  await expect(startInvestigation('AL.customer:123', 'rules', 'start-456')).resolves.toMatchObject({ incident_id: 'IN-123' });
  expect(fetchMock.mock.calls[0][1].body).toBe('{"alert_id":"AL.customer:123","mode":"rules"}');
});

it('启动调查失败保持错误，不重试写请求；拒绝不可信业务 ID', async () => {
  const fetchMock = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ error: {
    code: 'DEPENDENCY_UNAVAILABLE', message: '稍后再试', trace_id: 'TRACE-write',
  } }), { status: 503 })).mockResolvedValueOnce(new Response(JSON.stringify({
    investigation_id: 'INV-123', incident_id: '../bad', trace_id: 'TRACE-123', status: 'received', stream_url: '/api/v1/investigations/INV-123/stream',
  }), { status: 202 }));
  vi.stubGlobal('fetch', fetchMock);
  await expect(startInvestigation('AL-123', 'rules', 'start-789')).rejects.toMatchObject({ code: 'DEPENDENCY_UNAVAILABLE', traceId: 'TRACE-write' });
  expect(fetchMock).toHaveBeenCalledTimes(1);
  await expect(startInvestigation('AL-123', 'rules', 'start-789')).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
});
