import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

function request(id = 'IV-123', cursor?: string) {
  const url = new URL(`http://web.test/api/v1/investigations/${id}/stream`);
  if (cursor !== undefined) url.searchParams.set('cursor', cursor);
  url.searchParams.set('url', 'http://attacker.test');
  return new Request(url);
}

it('原样流式转发 SSE、游标和 trace，不缓冲事件体', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000/ignored');
  const stream = new ReadableStream<Uint8Array>({ start(controller) {
    controller.enqueue(new TextEncoder().encode('id: 3\nevent: evidence.added\ndata: {}\n\n'));
    controller.close();
  } });
  const upstream = vi.fn().mockResolvedValue(new Response(stream, { status: 200, headers: {
    'content-type': 'text/event-stream; charset=utf-8', 'x-trace-id': 'TRACE-123',
  } }));
  vi.stubGlobal('fetch', upstream);
  const response = await GET(request('IV-123', '2'), { params: Promise.resolve({ id: 'IV-123' }) });
  const [target, options] = upstream.mock.calls[0];
  expect(String(target)).toBe('http://backend.test:8000/api/v1/investigations/IV-123/stream');
  expect(options.headers['Last-Event-ID']).toBe('2');
  expect(options.redirect).toBe('manual');
  expect(response.status).toBe(200);
  expect(response.headers.get('content-type')).toContain('text/event-stream');
  expect(response.headers.get('cache-control')).toContain('no-transform');
  expect(response.headers.get('x-trace-id')).toBe('TRACE-123');
  expect(response.body).toBe(stream);
  expect(await response.text()).toContain('event: evidence.added');
});

it('自动重连时优先转发浏览器的 Last-Event-ID', async () => {
  const upstream = vi.fn().mockResolvedValue(new Response('event: status\ndata: {}\n\n', {
    headers: { 'content-type': 'text/event-stream' },
  }));
  vi.stubGlobal('fetch', upstream);
  const incoming = new Request(request('IV-123', '1').url, { headers: { 'Last-Event-ID': '4' } });
  await GET(incoming, { params: Promise.resolve({ id: 'IV-123' }) });
  expect(upstream.mock.calls[0][1].headers['Last-Event-ID']).toBe('4');
});

it('拒绝非法路径和游标，不访问上游', async () => {
  const upstream = vi.fn();
  vi.stubGlobal('fetch', upstream);
  const invalidId = await GET(request('bad.id'), { params: Promise.resolve({ id: 'bad.id' }) });
  const invalidCursor = await GET(request('IV-123', '-1'), { params: Promise.resolve({ id: 'IV-123' }) });
  expect(invalidId.status).toBe(400);
  expect(invalidCursor.status).toBe(400);
  expect(upstream).not.toHaveBeenCalled();
});

it('上游断线时返回可诊断的同源错误', async () => {
  vi.stubEnv('BACKEND_URL', 'http://private-backend.test:8000');
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('private-backend')));
  const response = await GET(request(), { params: Promise.resolve({ id: 'IV-123' }) });
  expect(response.status).toBe(503);
  expect(response.headers.get('x-trace-id')).toBeTruthy();
  expect(await response.text()).not.toContain('private-backend');
});

it('上游非 SSE 成功响应作为协议错误处理', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{}', {
    headers: { 'content-type': 'application/json' },
  })));
  const response = await GET(request(), { params: Promise.resolve({ id: 'IV-123' }) });
  expect(response.status).toBe(502);
});
