import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { POST as approve } from './route';
import { POST as reject } from '../reject/route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });
beforeEach(() => { vi.stubEnv('FRONTEND_ORIGIN', 'http://web.test'); });

function request(action: 'approve' | 'reject', body: unknown): Request {
  return new Request(`http://web.test/api/v1/response-plans/RP-123/${action}`, {
    method: 'POST', headers: {
      'Content-Type': 'application/json', 'Idempotency-Key': 'key-123',
      Origin: 'http://web.test', Host: 'web.test', Cookie: 'evidencesoc_demo_session=signed-token; unrelated=private',
    }, body: JSON.stringify(body),
  });
}
const context = { params: Promise.resolve({ id: 'RP-123' }) };
const planVersion = 'a'.repeat(64);

it('批准只转发一次并透传 202 已受理与 trace', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000');
  const accepted = { response_plan_id: 'RP-123', investigation_id: 'IV-123', incident_id: 'IN-123', trace_id: 'TRACE-202', decision: 'approved', status: 'accepted' };
  const mockedFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(accepted), { status: 202, headers: { 'x-trace-id': 'TRACE-202' } }));
  vi.stubGlobal('fetch', mockedFetch);
  const response = await approve(request('approve', { plan_version: planVersion, reason: '  已核对证据  ' }), context);
  expect(mockedFetch).toHaveBeenCalledTimes(1);
  expect(String(mockedFetch.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/response-plans/RP-123/approve');
  expect(JSON.parse(mockedFetch.mock.calls[0][1].body)).toEqual({ plan_version: planVersion, reason: '已核对证据' });
  expect(mockedFetch.mock.calls[0][1].headers['Idempotency-Key']).toBe('key-123');
  expect(mockedFetch.mock.calls[0][1].headers.Origin).toBe('http://web.test');
  expect(mockedFetch.mock.calls[0][1].headers.Cookie).toBe('evidencesoc_demo_session=signed-token');
  expect(response.status).toBe(202);
  expect(response.headers.get('x-trace-id')).toBe('TRACE-202');
  expect(await response.json()).toEqual(accepted);
});

it('拒绝时的 409 保留原始冲突，不重发', async () => {
  const error = { error: { code: 'ALREADY_DECIDED', message: 'Already decided.', trace_id: 'TRACE-409' } };
  const mockedFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(error), { status: 409 }));
  vi.stubGlobal('fetch', mockedFetch);
  const response = await reject(request('reject', { plan_version: planVersion, reason: '证据不足' }), context);
  expect(mockedFetch).toHaveBeenCalledTimes(1);
  expect(response.status).toBe(409);
  expect(await response.json()).toEqual(error);
});

it('空白字段、额外字段或无效编号直接拒绝', async () => {
  const mockedFetch = vi.fn();
  vi.stubGlobal('fetch', mockedFetch);
  for (const body of [{ plan_version: planVersion, reason: ' ' },
    { plan_version: planVersion, reason: 'why', decided_by: 'forged' },
    { plan_version: planVersion, reason: 'why', decision: 'approved' },
    { plan_version: 'stale', reason: 'why' }]) {
    expect((await approve(request('approve', body), context)).status).toBe(400);
  }
  expect((await approve(request('approve', { plan_version: planVersion, reason: 'why' }), { params: Promise.resolve({ id: '../escape' }) })).status).toBe(400);
  expect((await approve(new Request('http://web.test/api/v1/response-plans/RP-123/approve', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'http://web.test', Host: 'web.test', Cookie: 'evidencesoc_demo_session=signed-token' },
    body: JSON.stringify({ plan_version: planVersion, reason: 'why' }),
  }), context)).status).toBe(400);
  expect(mockedFetch).not.toHaveBeenCalled();
});

it('跨站 Origin 或非 JSON 写请求在代理层直接拒绝', async () => {
  const mockedFetch = vi.fn();
  vi.stubGlobal('fetch', mockedFetch);
  const body = JSON.stringify({ plan_version: planVersion, reason: '已核对证据' });
  const crossSite = new Request('http://web.test/api/v1/response-plans/RP-123/approve', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://other.test', Host: 'web.test', Cookie: 'evidencesoc_demo_session=signed-token' }, body,
  });
  const wrongType = new Request('http://web.test/api/v1/response-plans/RP-123/approve', {
    method: 'POST', headers: { 'Content-Type': 'text/plain', Origin: 'http://web.test', Host: 'web.test', Cookie: 'evidencesoc_demo_session=signed-token' }, body,
  });
  expect((await approve(crossSite, context)).status).toBe(403);
  expect((await approve(wrongType, context)).status).toBe(415);
  expect((await approve(new Request('http://web.test/api/v1/response-plans/RP-123/approve', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'key-123', Origin: 'http://web.test', Host: 'web.test' }, body,
  }), context)).status).toBe(401);
  expect(mockedFetch).not.toHaveBeenCalled();
});
