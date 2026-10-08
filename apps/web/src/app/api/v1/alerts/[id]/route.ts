import { randomUUID } from 'node:crypto';

export const runtime = 'nodejs';

function errorResponse(status: number, code: string, message: string): Response {
  const traceId = `WEB-${randomUUID()}`;
  return Response.json({ error: { code, message, trace_id: traceId } }, {
    status, headers: { 'Cache-Control': 'no-store', 'x-trace-id': traceId },
  });
}

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await params;
  if (typeof id !== 'string' || id.length < 1 || id.length > 64 || id === '.' || id === '..') {
    return errorResponse(400, 'INVALID_ALERT_ID', '告警编号无效。');
  }
  const timeout = AbortSignal.timeout(10_000);
  try {
    const backend = process.env.BACKEND_URL?.trim() || 'http://127.0.0.1:8000';
    const upstream = new URL(`/api/v1/alerts/${encodeURIComponent(id)}`, backend);
    if (!['http:', 'https:'].includes(upstream.protocol)) throw new Error('Unsupported protocol');
    const response = await fetch(upstream, {
      cache: 'no-store', redirect: 'manual', headers: { Accept: 'application/json' },
      signal: AbortSignal.any([request.signal, timeout]),
    });
    const body = await response.text();
    const headers = new Headers({
      'Content-Type': response.headers.get('content-type') || 'application/json',
      'Cache-Control': 'no-store',
    });
    const trace = response.headers.get('x-trace-id');
    if (trace) headers.set('x-trace-id', trace);
    return new Response([204, 205, 304].includes(response.status) ? null : body, { status: response.status, headers });
  } catch {
    if (request.signal.aborted) return errorResponse(499, 'REQUEST_CANCELLED', '请求已取消。');
    if (timeout.aborted) return errorResponse(504, 'UPSTREAM_TIMEOUT', '告警服务响应超时，请重试。');
    return errorResponse(503, 'ALERTS_UNAVAILABLE', '告警服务暂时不可用，请重试。');
  }
}
