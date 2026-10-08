import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

it('只向固定告警详情路径转发合法编号，并透传真实响应和 trace', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000/ignored');
  const record = { alert_id: 'AL-example', title: '真实告警', events: [] };
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(record), {
    status: 200, headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-detail' },
  }));
  vi.stubGlobal('fetch', fetchMock);
  const response = await GET(new Request('http://web.test/api/v1/alerts/AL-example?url=http://evil.test'),
    { params: Promise.resolve({ id: 'AL-example' }) });
  expect(String(fetchMock.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/alerts/AL-example');
  expect(fetchMock.mock.calls[0][1]).toMatchObject({ cache: 'no-store', redirect: 'manual' });
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(response.headers.get('x-trace-id')).toBe('TRACE-detail');
  expect(await response.json()).toEqual(record);
});

it('拒绝非法路径编号且不向上游发送请求', async () => {
  const fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
  const response = await GET(new Request('http://web.test/api/v1/alerts/bad'),
    { params: Promise.resolve({ id: '' }) });
  expect(response.status).toBe(400);
  expect(await response.json()).toMatchObject({ error: { code: 'INVALID_ALERT_ID' } });
  expect(fetchMock).not.toHaveBeenCalled();
});

it('点号与冒号是后端允许的告警编号字符', async () => {
  const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
  vi.stubGlobal('fetch', fetchMock);
  const response = await GET(new Request('http://web.test/api/v1/alerts/AL.customer%3A123'),
    { params: Promise.resolve({ id: 'AL.customer:123' }) });
  expect(response.status).toBe(200);
  expect(String(fetchMock.mock.calls[0][0])).toBe('http://127.0.0.1:8000/api/v1/alerts/AL.customer%3A123');
});

it('上游不存在时保留 404 错误体', async () => {
  const error = { error: { code: 'NOT_FOUND', message: 'Requested resource was not found.', trace_id: 'TRACE-404' } };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(error), {
    status: 404, headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-404' },
  })));
  const response = await GET(new Request('http://web.test/api/v1/alerts/AL-missing'),
    { params: Promise.resolve({ id: 'AL-missing' }) });
  expect(response.status).toBe(404);
  expect(await response.json()).toEqual(error);
});
