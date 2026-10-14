import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';
import { POST } from './demo/route';

const view = {
  actor_id: 'demo-reviewer', role: 'reviewer', allowed_actions: ['approve', 'reject'],
  expires_at: '2026-10-01T06:30:00Z',
};

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

it('GET 只将演示会话 cookie 转给固定后端', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000');
  const mockedFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(view)));
  vi.stubGlobal('fetch', mockedFetch);
  const response = await GET(new Request('http://web.test/api/v1/session', {
    headers: { Cookie: 'private=do-not-forward; evidencesoc_demo_session=token.signature' },
  }));
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual(view);
  expect(String(mockedFetch.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/session');
  expect(mockedFetch.mock.calls[0][1].headers.Cookie).toBe('evidencesoc_demo_session=token.signature');
  expect(response.headers.get('Cache-Control')).toBe('no-store');
});

it('GET 无演示会话时返回 401，不访问后端', async () => {
  const mockedFetch = vi.fn();
  vi.stubGlobal('fetch', mockedFetch);
  const response = await GET(new Request('http://web.test/api/v1/session'));
  expect(response.status).toBe(401);
  expect(mockedFetch).not.toHaveBeenCalled();
});

it('POST 限制同源并透传后端签发的 HttpOnly cookie', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000');
  vi.stubEnv('FRONTEND_ORIGIN', 'http://web.test');
  const cookie = 'evidencesoc_demo_session=token.signature; HttpOnly; SameSite=strict; Path=/; Max-Age=1800';
  const mockedFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(view), {
    headers: { 'Set-Cookie': cookie, 'x-trace-id': 'TRACE-1' },
  }));
  vi.stubGlobal('fetch', mockedFetch);
  const response = await POST(new Request('http://web.test/api/v1/session/demo', {
    method: 'POST', headers: { Origin: 'http://web.test', Host: 'web.test' },
  }));
  expect(response.status).toBe(200);
  expect(response.headers.get('set-cookie')).toBe(cookie);
  expect(response.headers.get('x-trace-id')).toBe('TRACE-1');
  expect(mockedFetch.mock.calls[0][1].headers.Origin).toBe('http://web.test');
  expect(mockedFetch.mock.calls[0][1].body).toBeUndefined();
});

it('POST 无 Origin、跨站或错误 Host 直接拒绝', async () => {
  vi.stubEnv('FRONTEND_ORIGIN', 'http://web.test');
  const mockedFetch = vi.fn();
  vi.stubGlobal('fetch', mockedFetch);
  for (const [url, origin] of [
    ['http://web.test/api/v1/session/demo', null],
    ['http://web.test/api/v1/session/demo', 'https://attacker.test'],
    ['http://other.test/api/v1/session/demo', 'http://other.test'],
  ] as const) {
    const headers: HeadersInit = origin ? { Origin: origin, Host: new URL(url).host } : { Host: new URL(url).host };
    const response = await POST(new Request(url, { method: 'POST', headers }));
    expect(response.status).toBe(403);
  }
  expect(mockedFetch).not.toHaveBeenCalled();
});
