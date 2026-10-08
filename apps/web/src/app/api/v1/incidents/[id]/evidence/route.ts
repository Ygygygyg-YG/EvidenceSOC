import { randomUUID } from 'node:crypto';

export const runtime = 'nodejs';

function proxyError(status: number, code: string, message: string): Response {
  const traceId = `WEB-${randomUUID()}`;
  return Response.json({ error: { code, message, trace_id: traceId } }, {
    status, headers: { 'Cache-Control': 'no-store', 'x-trace-id': traceId },
  });
}

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await params;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) return proxyError(400, 'INVALID_INCIDENT_ID', '案件编号无效。');
  const source = new URL(request.url).searchParams;
  const page = source.getAll('page');
  const pageSize = source.getAll('page_size');
  if (page.length > 1 || pageSize.length > 1 ||
    (page.length === 1 && (!/^[1-9][0-9]*$/.test(page[0]) || !Number.isSafeInteger(Number(page[0])))) ||
    (pageSize.length === 1 && (!/^[1-9][0-9]*$/.test(pageSize[0]) || Number(pageSize[0]) > 200))) {
    return proxyError(400, 'INVALID_PAGE', '证据分页参数无效。');
  }
  const timeout = AbortSignal.timeout(10_000);
  try {
    const backend = process.env.BACKEND_URL?.trim() || 'http://127.0.0.1:8000';
    const upstream = new URL(`/api/v1/incidents/${encodeURIComponent(id)}/evidence`, backend);
    if (!['http:', 'https:'].includes(upstream.protocol)) throw new Error('Unsupported protocol');
    if (page.length) upstream.searchParams.set('page', page[0]);
    if (pageSize.length) upstream.searchParams.set('page_size', pageSize[0]);
    const response = await fetch(upstream, {
      cache: 'no-store', redirect: 'manual', headers: { Accept: 'application/json' },
      signal: AbortSignal.any([request.signal, timeout]),
    });
    const body = await response.text();
    const headers = new Headers({
      'Content-Type': response.headers.get('content-type') || 'application/json',
      'Cache-Control': 'no-store',
    });
    const traceId = response.headers.get('x-trace-id');
    if (traceId) headers.set('x-trace-id', traceId);
    return new Response([204, 205, 304].includes(response.status) ? null : body, { status: response.status, headers });
  } catch {
    if (request.signal.aborted) return proxyError(499, 'REQUEST_CANCELLED', '请求已取消。');
    if (timeout.aborted) return proxyError(504, 'UPSTREAM_TIMEOUT', '证据服务超时，请重试。');
    return proxyError(503, 'EVIDENCE_UNAVAILABLE', '证据服务暂时不可用，请重试。');
  }
}
