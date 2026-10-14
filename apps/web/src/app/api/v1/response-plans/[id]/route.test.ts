import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

it('详情以编码后的方案编号请求后端并保留 404', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000');
  const error = { error: { code: 'NOT_FOUND', message: 'Plan not found.', trace_id: 'TRACE-404' } };
  const mockedFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(error), { status: 404, headers: { 'x-trace-id': 'TRACE-404' } }));
  vi.stubGlobal('fetch', mockedFetch);
  const response = await GET(new Request('http://web.test/api/v1/response-plans/RP-123'), { params: Promise.resolve({ id: 'RP-123' }) });
  expect(String(mockedFetch.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/response-plans/RP-123');
  expect(response.status).toBe(404);
  expect(await response.json()).toEqual(error);
});

it('无效的方案编号不会发起请求', async () => {
  const mockedFetch = vi.fn();
  vi.stubGlobal('fetch', mockedFetch);
  const response = await GET(new Request('http://web.test/api/v1/response-plans/x'), { params: Promise.resolve({ id: '../escape' }) });
  expect(response.status).toBe(400);
  expect(mockedFetch).not.toHaveBeenCalled();
});
