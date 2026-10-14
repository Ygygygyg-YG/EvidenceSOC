import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

const context = { params: Promise.resolve({ id: 'IN-123' }) };
afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

it('只转发授权案件的分页字段和后端状态', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000');
  const body = { items: [], total: 0, page: 2, page_size: 20 };
  const mockedFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), {
    headers: { 'x-trace-id': 'TRACE-page' },
  }));
  vi.stubGlobal('fetch', mockedFetch);
  const response = await GET(new Request('http://web.test/api/v1/incidents/IN-123/evidence?page=2&page_size=20&ignored=secret'), context);
  expect(String(mockedFetch.mock.calls[0][0])).toBe('http://backend.test:8000/api/v1/incidents/IN-123/evidence?page=2&page_size=20');
  expect(response.status).toBe(200);
  expect(response.headers.get('x-trace-id')).toBe('TRACE-page');
  expect(await response.json()).toEqual(body);
});

it('无效案件编号、页码和重复分页字段在代理层拒绝', async () => {
  const mockedFetch = vi.fn();
  vi.stubGlobal('fetch', mockedFetch);
  const cases = [
    [new Request('http://web.test/api/v1/incidents/IN-123/evidence?page=0'), context],
    [new Request('http://web.test/api/v1/incidents/IN-123/evidence?page_size=500'), context],
    [new Request('http://web.test/api/v1/incidents/IN-123/evidence?page=1&page=2'), context],
    [new Request('http://web.test/api/v1/incidents/bad/evidence'), { params: Promise.resolve({ id: '../bad' }) }],
  ] as const;
  for (const [request, params] of cases) expect((await GET(request, params)).status).toBe(400);
  expect(mockedFetch).not.toHaveBeenCalled();
});
