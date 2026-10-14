import { randomUUID } from 'node:crypto';

export const runtime = 'nodejs';

const identifier = /^[A-Za-z0-9_-]{1,64}$/;
const cursorPattern = /^[0-9]{1,20}$/;

function proxyError(status: number, code: string, message: string): Response {
  const traceId = `WEB-${randomUUID()}`;
  return Response.json({ error: { code, message, trace_id: traceId } }, {
    status, headers: { 'Cache-Control': 'no-store', 'x-trace-id': traceId },
  });
}

export async function GET(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await context.params;
  if (!identifier.test(id)) return proxyError(400, 'INVALID_INVESTIGATION_ID', '调查编号无效。');
  const cursor = request.headers.get('last-event-id') ?? new URL(request.url).searchParams.get('cursor');
  if (cursor !== null && !cursorPattern.test(cursor)) {
    return proxyError(400, 'INVALID_CURSOR', '事件游标无效。');
  }

  const connectController = new AbortController();
  const connectTimer = setTimeout(() => connectController.abort(), 10_000);
  try {
    const backend = process.env.BACKEND_URL?.trim() || 'http://127.0.0.1:8000';
    const upstream = new URL(`/api/v1/investigations/${encodeURIComponent(id)}/stream`, backend);
    if (!['http:', 'https:'].includes(upstream.protocol)) throw new Error('Unsupported protocol');
    const headers: Record<string, string> = { Accept: 'text/event-stream' };
    if (cursor !== null) headers['Last-Event-ID'] = cursor;
    const response = await fetch(upstream, {
      cache: 'no-store', redirect: 'manual', headers,
      signal: AbortSignal.any([request.signal, connectController.signal]),
    });
    clearTimeout(connectTimer);
    const trace = response.headers.get('x-trace-id');
    if (response.status === 200 && response.headers.get('content-type')?.startsWith('text/event-stream') && response.body) {
      const outgoing = new Headers({
        'Content-Type': response.headers.get('content-type') || 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'X-Accel-Buffering': 'no',
      });
      if (trace) outgoing.set('x-trace-id', trace);
      return new Response(response.body, { status: 200, headers: outgoing });
    }
    if (response.status >= 400 && response.headers.get('content-type')?.includes('application/json')) {
      const outgoing = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      if (trace) outgoing.set('x-trace-id', trace);
      return new Response(await response.text(), { status: response.status, headers: outgoing });
    }
    return proxyError(502, 'INVALID_STREAM', '调查事件流返回了无效响应。');
  } catch {
    clearTimeout(connectTimer);
    if (request.signal.aborted) return proxyError(499, 'REQUEST_CANCELLED', '请求已取消。');
    if (connectController.signal.aborted) return proxyError(504, 'UPSTREAM_TIMEOUT', '调查事件流连接超时。');
    return proxyError(503, 'STREAM_UNAVAILABLE', '调查事件流暂时不可用。');
  }
}
