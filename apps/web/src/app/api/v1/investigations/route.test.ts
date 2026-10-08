import { afterEach, expect, it, vi } from 'vitest';
import { POST } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

function request(body: unknown, key: string | null = 'start-123', options: {
  cookie?: string; origin?: string | null; host?: string | null;
} = {}): Request {
  return new Request('http://web.test/api/v1/investigations', {
    method: 'POST', headers: {
      'Content-Type': 'application/json', ...(key ? { 'Idempotency-Key': key } : {}),
      ...(options.cookie === undefined ? { Cookie: 'evidencesoc_demo_session=valid-token; analytics=private' } : { Cookie: options.cookie }),
      ...(options.origin === undefined ? { Origin: 'http://web.test' } : options.origin ? { Origin: options.origin } : {}),
      ...(options.host === undefined ? { Host: 'web.test' } : options.host ? { Host: options.host } : {}),
    },
    body: JSON.stringify(body),
  });
}

it('只转发 alert_id、明确模式与幂等键，使用真实后端业务 ID 且不自动重试', async () => {
  vi.stubEnv('FRONTEND_ORIGIN', 'http://web.test');
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000/ignored');
  const accepted = { investigation_id: 'INV-123', incident_id: 'IN-123', trace_id: 'TRACE-123', status: 'collecting', stream_url: '/api/v1/investigations/INV-123/stream' };
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(accepted), {
    status: 202, headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-123' },
  }));
  vi.stubGlobal('fetch', fetchMock);
  const response = await POST(request({ alert_id: 'AL-123', mode: 'rules' }));
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(String(fetchMock.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/investigations');
  expect(fetchMock.mock.calls[0][1]).toMatchObject({
    method: 'POST', cache: 'no-store', redirect: 'manual', body: '{"alert_id":"AL-123","mode":"rules"}',
  });
  expect(new Headers(fetchMock.mock.calls[0][1].headers).get('Idempotency-Key')).toBe('start-123');
  expect(new Headers(fetchMock.mock.calls[0][1].headers).get('Origin')).toBe('http://web.test');
  expect(new Headers(fetchMock.mock.calls[0][1].headers).get('Cookie')).toBe('evidencesoc_demo_session=valid-token');
  expect(response.status).toBe(202);
  expect(response.headers.get('x-trace-id')).toBe('TRACE-123');
  expect(await response.json()).toEqual(accepted);
});

it('不接受缺失模式、未知模式、另一个 incident_id 字段或缺失幂等键', async () => {
  vi.stubEnv('FRONTEND_ORIGIN', 'http://web.test');
  const fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
  for (const [body, key] of [
    [{ alert_id: 'AL-123' }, 'start-123'],
    [{ alert_id: 'AL-123', mode: 'other' }, 'start-123'],
    [{ incident_id: 'IN-123', mode: 'rules' }, 'start-123'],
    [{ alert_id: '', mode: 'rules' }, 'start-123'],
    [{ alert_id: 'AL-123', mode: 'rules' }, null],
  ] as const) {
    const response = await POST(request(body, key));
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: { code: 'INVALID_REQUEST' } });
  }
  expect(fetchMock).not.toHaveBeenCalled();
});

it('保留后端冲突状态和 trace，避免在代理层伪造成功', async () => {
  vi.stubEnv('FRONTEND_ORIGIN', 'http://web.test');
  const error = { error: { code: 'CONFLICT', message: 'Investigation already exists.', trace_id: 'TRACE-conflict' } };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(error), {
    status: 409, headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-conflict' },
  })));
  const response = await POST(request({ alert_id: 'AL-123', mode: 'rules' }));
  expect(response.status).toBe(409);
  expect(await response.json()).toEqual(error);
});

it('拒绝无专用会话 Cookie、缺失或不可信 Origin/Host，且不调用后端', async () => {
  vi.stubEnv('FRONTEND_ORIGIN', 'http://web.test');
  const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock);
  const body = { alert_id: 'AL-123', mode: 'rules' };
  expect((await POST(request(body, 'start-123', { cookie: 'analytics=private' }))).status).toBe(401);
  for (const options of [
    { origin: null }, { origin: 'https://evil.test' }, { host: null }, { host: 'evil.test' },
  ]) {
    const response = await POST(request(body, 'start-123', options));
    expect(response.status).toBe(403);
  }
  expect(fetchMock).not.toHaveBeenCalled();
});
