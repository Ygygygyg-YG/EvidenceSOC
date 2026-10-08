import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

it('只向固定案件列表路径转发支持的查询字段', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000/ignored');
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, page: 2, page_size: 50 }), {
    status: 200, headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-list' },
  }));
  vi.stubGlobal('fetch', fetchMock);
  const response = await GET(new Request('http://web.test/api/v1/incidents?page=2&page_size=50&status=failed&url=http://evil.test'));
  expect(String(fetchMock.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/incidents?page=2&page_size=50&status=failed');
  expect(fetchMock.mock.calls[0][1]).toMatchObject({ cache: 'no-store', redirect: 'manual' });
  expect(response.headers.get('x-trace-id')).toBe('TRACE-list');
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(await response.json()).toMatchObject({ total: 0 });
});

it('转发高危和时间范围，不转发未知字段', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000');
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 20 }), { status: 200 }));
  vi.stubGlobal('fetch', fetchMock);
  await GET(new Request('http://web.test/api/v1/incidents?risk=high&time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z&redirect=http://evil.test'));
  expect(String(fetchMock.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/incidents?risk=high&time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
});

it('保留后端错误状态与错误体，不伪造空列表', async () => {
  const error = { error: { code: 'INVALID_REQUEST', message: 'Bad filter', trace_id: 'TRACE-invalid' } };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(error), { status: 422 })));
  const response = await GET(new Request('http://web.test/api/v1/incidents?status=bad'));
  expect(response.status).toBe(422);
  expect(await response.json()).toEqual(error);
});
