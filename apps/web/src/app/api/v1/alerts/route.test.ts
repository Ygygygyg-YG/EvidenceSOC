import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

it('固定告警路径，仅转发支持的 query，成功响应不缓存', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000/ignored-prefix');
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, page: 2, page_size: 50 }), {
    status: 200, headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-proxy' },
  }));
  vi.stubGlobal('fetch', fetchMock);
  const response = await GET(new Request('http://web.test/api/v1/alerts?page=2&page_size=50&severity=high&status=manual_review&extra=ignored&url=http://wrong.test'));
  const [target, options] = fetchMock.mock.calls[0];
  expect(String(target)).toBe('http://backend.test:8000/api/v1/alerts?page=2&page_size=50&severity=high&status=manual_review');
  expect(options).toMatchObject({ cache: 'no-store', redirect: 'manual' });
  expect(options.signal).toBeInstanceOf(AbortSignal);
  expect(response.headers.get('x-trace-id')).toBe('TRACE-proxy');
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(await response.json()).toMatchObject({ total: 0, page: 2 });
});

it('只转发允许的时间窗口和关键词查询参数', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 20 }))));
  await GET(new Request('http://web.test/api/v1/alerts?time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z&query=SQL&secret=hidden'));
  const target = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as URL;
  expect(target.searchParams.get('time_from')).toBe('2026-09-30T00:00:00Z');
  expect(target.searchParams.get('time_to')).toBe('2026-10-01T00:00:00Z');
  expect(target.searchParams.get('query')).toBe('SQL');
  expect(target.searchParams.has('secret')).toBe(false);
});

it('透传后端 HTTP 状态、错误 JSON 和 trace 头', async () => {
  const error = { error: { code: 'INVALID_REQUEST', message: 'Invalid severity.', trace_id: 'TRACE-validation' } };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(error), {
    status: 422, headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-validation' },
  })));
  const response = await GET(new Request('http://web.test/api/v1/alerts?severity=bad'));
  expect(response.status).toBe(422);
  expect(await response.json()).toEqual(error);
  expect(response.headers.get('x-trace-id')).toBe('TRACE-validation');
});

function waitingFetch(_target: unknown, options?: RequestInit): Promise<Response> {
  return new Promise((_resolve, reject) => {
    const signal = options?.signal;
    if (signal?.aborted) reject(signal.reason);
    else signal?.addEventListener('abort', () => reject(signal.reason), { once: true });
  });
}

it('浏览器取消请求时取消上游读取', async () => {
  vi.stubGlobal('fetch', vi.fn(waitingFetch));
  const controller = new AbortController();
  const result = GET(new Request('http://web.test/api/v1/alerts', { signal: controller.signal }));
  controller.abort();
  const response = await result;
  expect(response.status).toBe(499);
  expect(await response.json()).toMatchObject({ error: { code: 'REQUEST_CANCELLED' } });
});

it('超时返回明确错误，且不泄露服务端配置', async () => {
  vi.stubEnv('BACKEND_URL', 'http://private-backend.test:8000');
  const timeout = new AbortController();
  const timeoutMock = vi.spyOn(AbortSignal, 'timeout').mockReturnValue(timeout.signal);
  vi.stubGlobal('fetch', vi.fn(waitingFetch));
  const result = GET(new Request('http://web.test/api/v1/alerts'));
  timeout.abort(new DOMException('deadline', 'TimeoutError'));
  const response = await result;
  expect(timeoutMock).toHaveBeenCalledWith(10_000);
  expect(response.status).toBe(504);
  expect(await response.text()).not.toContain('private-backend');
  expect(response.headers.get('x-trace-id')).toBeTruthy();
});
