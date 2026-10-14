import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const context = { params: Promise.resolve({ id: 'RP-123' }) };
const planVersion = 'a'.repeat(64);

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });
beforeEach(() => {
  vi.stubEnv('FRONTEND_ORIGIN', 'http://web.test');
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000');
});

function request(origin = 'http://web.test', cookie = 'evidencesoc_demo_session=signed-token; unrelated=private'): Request {
  return new Request('http://web.test/api/v1/response-plans/RP-123/renew', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json', 'Idempotency-Key': 'renew-123',
      Origin: origin, Host: 'web.test', Cookie: cookie,
    },
    body: JSON.stringify({ plan_version: planVersion }),
  });
}

it('续办只转发一次，保留服务端 202 与提交标识', async () => {
  const accepted = { response_plan_id: 'RP-123', investigation_id: 'IV-123', incident_id: 'IN-123', trace_id: 'TRACE-renew', status: 'accepted', stream_url: '/api/v1/investigations/IV-123/stream' };
  const upstream = vi.fn().mockResolvedValue(new Response(JSON.stringify(accepted), { status: 202, headers: { 'x-trace-id': 'TRACE-renew' } }));
  vi.stubGlobal('fetch', upstream);
  const { POST } = await import('./route');
  const response = await POST(request(), context);
  expect(upstream).toHaveBeenCalledTimes(1);
  expect(String(upstream.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/response-plans/RP-123/renew');
  expect(upstream.mock.calls[0][1].headers).toMatchObject({
    'Idempotency-Key': 'renew-123', Origin: 'http://web.test', Cookie: 'evidencesoc_demo_session=signed-token',
  });
  expect(JSON.parse(upstream.mock.calls[0][1].body)).toEqual({ plan_version: planVersion });
  expect(response.status).toBe(202);
  expect(response.headers.get('x-trace-id')).toBe('TRACE-renew');
  expect(await response.json()).toEqual(accepted);
});

it('跨站、无会话与无效方案版本均在本地拒绝', async () => {
  const upstream = vi.fn();
  vi.stubGlobal('fetch', upstream);
  const { POST } = await import('./route');
  expect((await POST(request('https://evil.test'), context)).status).toBe(403);
  expect((await POST(request('http://web.test', ''), context)).status).toBe(401);
  const invalid = new Request('http://web.test/api/v1/response-plans/RP-123/renew', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'renew-123', Origin: 'http://web.test', Host: 'web.test', Cookie: 'evidencesoc_demo_session=signed-token' },
    body: JSON.stringify({ plan_version: 'stale' }),
  });
  expect((await POST(invalid, context)).status).toBe(400);
  expect(upstream).not.toHaveBeenCalled();
});
