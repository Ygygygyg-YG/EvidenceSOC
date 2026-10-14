import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

it('数据源健康代理只访问固定上游路径并保留 trace', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000/ignored');
  const upstream = vi.fn().mockResolvedValue(new Response('{"sources":[]}', {
    headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-health' },
  }));
  vi.stubGlobal('fetch', upstream);
  const response = await GET(new Request('http://web.test/api/v1/data-sources/health?url=http://attacker.test'));
  expect(String(upstream.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/data-sources/health');
  expect(response.headers.get('x-trace-id')).toBe('TRACE-health');
  expect(response.headers.get('cache-control')).toBe('no-store');
});
