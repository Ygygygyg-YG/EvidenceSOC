import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

it('只转发窗口白名单并保留后端 trace', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000/ignored');
  const upstream = vi.fn().mockResolvedValue(new Response('{"window":"1h"}', {
    headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-dashboard' },
  }));
  vi.stubGlobal('fetch', upstream);
  const response = await GET(new Request('http://web.test/api/v1/dashboard/summary?window=1h&url=http://attacker.test'));
  expect(String(upstream.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/dashboard/summary?window=1h');
  expect(response.headers.get('x-trace-id')).toBe('TRACE-dashboard');
  expect(response.headers.get('cache-control')).toBe('no-store');
});

it('断线时返回可诊断错误且不泄露上游地址', async () => {
  vi.stubEnv('BACKEND_URL', 'http://private-backend.test:8000');
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('private-backend')));
  const response = await GET(new Request('http://web.test/api/v1/dashboard/summary'));
  expect(response.status).toBe(503);
  expect(response.headers.get('x-trace-id')).toBeTruthy();
  expect(await response.text()).not.toContain('private-backend');
});
