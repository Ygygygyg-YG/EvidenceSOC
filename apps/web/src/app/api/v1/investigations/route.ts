import { randomUUID } from 'node:crypto';
import { demoSessionCookie, trustedWriteOrigin } from '../session/guard';

export const runtime = 'nodejs';

function errorResponse(status: number, code: string, message: string): Response {
  const traceId = `WEB-${randomUUID()}`;
  return Response.json({ error: { code, message, trace_id: traceId } }, {
    status, headers: { 'Cache-Control': 'no-store', 'x-trace-id': traceId },
  });
}

export async function POST(request: Request): Promise<Response> {
  const origin = trustedWriteOrigin(request);
  if (!origin) return errorResponse(403, 'CROSS_ORIGIN_REQUEST', '不接受跨站调查请求。');
  const cookie = demoSessionCookie(request);
  if (!cookie) return errorResponse(401, 'SESSION_REQUIRED', '请先启用本地演示账户。');
  const idempotencyKey = request.headers.get('Idempotency-Key');
  if (!idempotencyKey || !/^[A-Za-z0-9_-]{1,128}$/.test(idempotencyKey)) {
    return errorResponse(400, 'INVALID_REQUEST', '需要有效的 Idempotency-Key。');
  }
  let body: unknown;
  try {
    const raw = await request.text();
    if (raw.length > 4096) return errorResponse(400, 'INVALID_REQUEST', '请求数据无效。');
    body = JSON.parse(raw);
  } catch {
    return errorResponse(400, 'INVALID_REQUEST', '请求数据无效。');
  }
  if (body === null || typeof body !== 'object' || Array.isArray(body)
    || Object.keys(body).length !== 2 || !Object.hasOwn(body, 'alert_id') || !Object.hasOwn(body, 'mode')
    || typeof (body as { alert_id?: unknown }).alert_id !== 'string'
    || (body as { alert_id: string }).alert_id.length < 1
    || (body as { alert_id: string }).alert_id.length > 64
    || !['rules', 'model'].includes(String((body as { mode?: unknown }).mode))) {
    return errorResponse(400, 'INVALID_REQUEST', '需要有效的告警编号和执行模式。');
  }
  const alertId = (body as { alert_id: string }).alert_id;
  const mode = (body as { mode: 'rules' | 'model' }).mode;
  const timeout = AbortSignal.timeout(20_000);
  try {
    const backend = process.env.BACKEND_URL?.trim() || 'http://127.0.0.1:8000';
    const upstream = new URL('/api/v1/investigations', backend);
    if (!['http:', 'https:'].includes(upstream.protocol)) throw new Error('Unsupported protocol');
    const response = await fetch(upstream, {
      method: 'POST', body: JSON.stringify({ alert_id: alertId, mode }),
      cache: 'no-store', redirect: 'manual',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey, Origin: origin, Cookie: cookie },
      signal: AbortSignal.any([request.signal, timeout]),
    });
    const responseBody = await response.text();
    const headers = new Headers({
      'Content-Type': response.headers.get('content-type') || 'application/json',
      'Cache-Control': 'no-store',
    });
    const trace = response.headers.get('x-trace-id');
    if (trace) headers.set('x-trace-id', trace);
    return new Response([204, 205, 304].includes(response.status) ? null : responseBody, { status: response.status, headers });
  } catch {
    if (request.signal.aborted) return errorResponse(499, 'REQUEST_CANCELLED', '请求已取消。');
    if (timeout.aborted) return errorResponse(504, 'UPSTREAM_TIMEOUT', '启动调查超时。请刷新告警详情，确认是否已经创建调查。');
    return errorResponse(503, 'INVESTIGATIONS_UNAVAILABLE', '调查服务暂时不可用。请刷新告警详情，确认是否已经创建调查。');
  }
}
