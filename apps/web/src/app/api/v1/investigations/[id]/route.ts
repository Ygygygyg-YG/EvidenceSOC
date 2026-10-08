import { randomUUID } from 'node:crypto';

export const runtime = 'nodejs';

const identifier = /^[A-Za-z0-9_-]{1,64}$/;

function proxyError(status: number, code: string, message: string): Response {
  const traceId = `WEB-${randomUUID()}`;
  return Response.json({ error: { code, message, trace_id: traceId } }, {
    status, headers: { 'Cache-Control': 'no-store', 'x-trace-id': traceId },
  });
}

export async function GET(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await context.params;
  if (!identifier.test(id)) return proxyError(400, 'INVALID_INVESTIGATION_ID', '调查编号无效。');
  const timeout = AbortSignal.timeout(10_000);
  try {
    const backend = process.env.BACKEND_URL?.trim() || 'http://127.0.0.1:8000';
    const upstream = new URL(`/api/v1/investigations/${encodeURIComponent(id)}`, backend);
    if (!['http:', 'https:'].includes(upstream.protocol)) throw new Error('Unsupported protocol');
    const response = await fetch(upstream, {
      cache: 'no-store', redirect: 'manual', headers: { Accept: 'application/json' },
      signal: AbortSignal.any([request.signal, timeout]),
    });
    const headers = new Headers({
      'Content-Type': response.headers.get('content-type') || 'application/json',
      'Cache-Control': 'no-store',
    });
    const trace = response.headers.get('x-trace-id');
    if (trace) headers.set('x-trace-id', trace);
    return new Response([204, 205, 304].includes(response.status) ? null : await response.text(), {
      status: response.status, headers,
    });
  } catch {
    if (request.signal.aborted) return proxyError(499, 'REQUEST_CANCELLED', '请求已取消。');
    if (timeout.aborted) return proxyError(504, 'UPSTREAM_TIMEOUT', '调查快照读取超时，请重试。');
    return proxyError(503, 'SNAPSHOT_UNAVAILABLE', '调查快照暂时不可用，请重试。');
  }
}
