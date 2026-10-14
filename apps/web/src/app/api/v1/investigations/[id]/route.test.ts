import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

it('调查快照只代理合法编号，保留上游状态与 trace', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000/ignored');
  const upstream = vi.fn().mockResolvedValue(new Response('{"revision":"2"}', {
    headers: { 'x-trace-id': 'TRACE-snapshot' },
  }));
  vi.stubGlobal('fetch', upstream);
  const response = await GET(new Request('http://web.test/api/v1/investigations/IV-123'), {
    params: Promise.resolve({ id: 'IV-123' }),
  });
  expect(String(upstream.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/investigations/IV-123');
  expect(response.headers.get('x-trace-id')).toBe('TRACE-snapshot');
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect((await GET(new Request('http://web.test/api/v1/investigations/escape'), {
    params: Promise.resolve({ id: '../escape' }),
  })).status).toBe(400);
  expect(upstream).toHaveBeenCalledTimes(1);
});
