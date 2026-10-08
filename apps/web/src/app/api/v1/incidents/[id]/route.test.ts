import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

function request(id: string) {
  return new Request(`http://web.test/api/v1/incidents/${encodeURIComponent(id)}?url=http://other.test`);
}

it('固定案件路径，不转发任意 query，成功响应不缓存', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000/ignored-prefix');
  const upstream = vi.fn().mockResolvedValue(new Response(JSON.stringify({ incident_id: 'IN-123' }), {
    status: 200, headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-incident' },
  }));
  vi.stubGlobal('fetch', upstream);
  const response = await GET(request('IN-123'), { params: Promise.resolve({ id: 'IN-123' }) });
  const [target, options] = upstream.mock.calls[0];
  expect(String(target)).toBe('http://backend.test:8000/api/v1/incidents/IN-123');
  expect(options).toMatchObject({ cache: 'no-store', redirect: 'manual' });
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(response.headers.get('x-trace-id')).toBe('TRACE-incident');
  expect(await response.json()).toEqual({ incident_id: 'IN-123' });
});

it('透传案件 404 错误和 trace', async () => {
  const error = { error: { code: 'NOT_FOUND', message: 'incident does not exist', trace_id: 'TRACE-not-found' } };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(error), {
    status: 404, headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-not-found' },
  })));
  const response = await GET(request('IN-MISSING'), { params: Promise.resolve({ id: 'IN-MISSING' }) });
  expect(response.status).toBe(404);
  expect(response.headers.get('x-trace-id')).toBe('TRACE-not-found');
  expect(await response.json()).toEqual(error);
});

it('拒绝不合法的案件 ID，避免访问任意上游路径', async () => {
  const upstream = vi.fn();
  vi.stubGlobal('fetch', upstream);
  const response = await GET(request('../alerts'), { params: Promise.resolve({ id: '../alerts' }) });
  expect(response.status).toBe(400);
  expect(upstream).not.toHaveBeenCalled();
});

it('上游断连返回可诊断错误，不暴露服务端地址', async () => {
  vi.stubEnv('BACKEND_URL', 'http://private-backend.test:8000');
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('private-backend')));
  const response = await GET(request('IN-123'), { params: Promise.resolve({ id: 'IN-123' }) });
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain('private-backend');
  expect(response.headers.get('x-trace-id')).toBeTruthy();
});
