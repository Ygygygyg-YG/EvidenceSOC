import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

it('只转发响应列表允许的查询字段与后端真实分页', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000/ignored');
  const payload = { items: [], total: 0, page: 2, page_size: 50 };
  const mockedFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), { status: 200, headers: { 'x-trace-id': 'TRACE-LIST' } }));
  vi.stubGlobal('fetch', mockedFetch);
  const response = await GET(new Request('http://web.test/api/v1/response-plans?page=2&page_size=50&decision_state=pending&secret=ignored'));
  expect(String(mockedFetch.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/response-plans?page=2&page_size=50&decision_state=pending');
  expect(mockedFetch.mock.calls[0][1]).toMatchObject({ cache: 'no-store', redirect: 'manual' });
  expect(await response.json()).toEqual(payload);
  expect(response.headers.get('x-trace-id')).toBe('TRACE-LIST');
});

it('后端不可用返回明确的 503 错误，不伪造空列表', async () => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')));
  const response = await GET(new Request('http://web.test/api/v1/response-plans?page=1&page_size=20'));
  expect(response.status).toBe(503);
  expect(await response.json()).toMatchObject({ error: { code: 'RESPONSES_UNAVAILABLE' } });
});
