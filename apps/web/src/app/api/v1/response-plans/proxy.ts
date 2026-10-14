import { randomUUID } from 'node:crypto';

const planIdPattern = /^[A-Za-z0-9_-]{1,64}$/;

export function validPlanId(id: string): boolean { return planIdPattern.test(id); }

export function proxyError(status: number, code: string, message: string): Response {
  const traceId = `WEB-${randomUUID()}`;
  return Response.json({ error: { code, message, trace_id: traceId } }, {
    status, headers: { 'Cache-Control': 'no-store', 'x-trace-id': traceId },
  });
}

function backendUrl(path: string): URL {
  const backend = process.env.BACKEND_URL?.trim() || 'http://127.0.0.1:8000';
  const upstream = new URL(path, backend);
  if (!['http:', 'https:'].includes(upstream.protocol)) throw new Error('Unsupported backend URL');
  return upstream;
}

function forwardResponse(response: Response, body: string): Response {
  const headers = new Headers({
    'Content-Type': response.headers.get('content-type') || 'application/json',
    'Cache-Control': 'no-store',
  });
  const traceId = response.headers.get('x-trace-id');
  if (traceId) headers.set('x-trace-id', traceId);
  return new Response([204, 205, 304].includes(response.status) ? null : body, { status: response.status, headers });
}

export async function proxyGet(request: Request, path: string, queryKeys: readonly string[] = []): Promise<Response> {
  const timeout = AbortSignal.timeout(10_000);
  try {
    const upstream = backendUrl(path);
    const query = new URL(request.url).searchParams;
    for (const key of queryKeys) {
      for (const value of query.getAll(key)) upstream.searchParams.append(key, value);
    }
    const response = await fetch(upstream, {
      cache: 'no-store', redirect: 'manual', headers: { Accept: 'application/json' },
      signal: AbortSignal.any([request.signal, timeout]),
    });
    return forwardResponse(response, await response.text());
  } catch {
    if (request.signal.aborted) return proxyError(499, 'REQUEST_CANCELLED', '请求已取消。');
    if (timeout.aborted) return proxyError(504, 'UPSTREAM_TIMEOUT', '响应服务超时，请重试。');
    return proxyError(503, 'RESPONSES_UNAVAILABLE', '响应服务暂时不可用，请重试。');
  }
}

export async function proxyDecision(request: Request, planId: string, action: 'approve' | 'reject'): Promise<Response> {
  if (!validPlanId(planId)) return proxyError(400, 'INVALID_PLAN_ID', '响应方案编号无效。');
  const configuredOrigin = process.env.FRONTEND_ORIGIN?.trim() || 'http://127.0.0.1:3000';
  const origin = request.headers.get('origin');
  try {
    if (!origin || origin !== configuredOrigin || request.headers.get('host') !== new URL(configuredOrigin).host) {
      return proxyError(403, 'CROSS_ORIGIN_REQUEST', '不接受跨站审批请求。');
    }
  } catch {
    return proxyError(403, 'CROSS_ORIGIN_REQUEST', '不接受跨站审批请求。');
  }
  if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return proxyError(415, 'UNSUPPORTED_MEDIA_TYPE', '审批请求必须使用 JSON。');
  }
  const sessionCookies = (request.headers.get('cookie') ?? '').split(';').map((cookie) => cookie.trim())
    .filter((cookie) => cookie.startsWith('evidencesoc_demo_session='));
  if (sessionCookies.length !== 1 || sessionCookies[0].length === 'evidencesoc_demo_session='.length) {
    return proxyError(401, 'SESSION_REQUIRED', '请先启用本地演示会话。');
  }
  const idempotencyKey = request.headers.get('idempotency-key');
  if (!idempotencyKey || !/^[\x21-\x7e]{1,255}$/.test(idempotencyKey)) {
    return proxyError(400, 'INVALID_IDEMPOTENCY_KEY', '提交标识无效。');
  }
  let input: unknown;
  try {
    const raw = await request.text();
    if (raw.length > 4096) return proxyError(400, 'INVALID_REQUEST', '请求数据无效。');
    input = JSON.parse(raw);
  } catch {
    return proxyError(400, 'INVALID_REQUEST', '请求数据无效。');
  }
  if (input === null || typeof input !== 'object' || Array.isArray(input)
    || Object.keys(input).length !== 2 || !Object.hasOwn(input, 'plan_version')
    || !Object.hasOwn(input, 'reason')) {
    return proxyError(400, 'INVALID_REQUEST', '只接受方案版本和决定理由。');
  }
  const candidate = input as { plan_version?: unknown; reason?: unknown };
  if (typeof candidate.plan_version !== 'string' || !/^[a-f0-9]{64}$/.test(candidate.plan_version)
    || typeof candidate.reason !== 'string') {
    return proxyError(400, 'INVALID_REQUEST', '方案版本或决定理由无效。');
  }
  const reason = candidate.reason.trim();
  if (!reason || reason.length > 2000) {
    return proxyError(400, 'INVALID_REQUEST', '决定理由无效。');
  }
  const timeout = AbortSignal.timeout(20_000);
  try {
    const upstream = backendUrl(`/api/v1/response-plans/${encodeURIComponent(planId)}/${action}`);
    const response = await fetch(upstream, {
      method: 'POST', cache: 'no-store', redirect: 'manual',
      headers: {
        Accept: 'application/json', 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey,
        Origin: origin, Cookie: sessionCookies[0],
      },
      body: JSON.stringify({ plan_version: candidate.plan_version, reason }),
      signal: AbortSignal.any([request.signal, timeout]),
    });
    return forwardResponse(response, await response.text());
  } catch {
    if (request.signal.aborted) return proxyError(499, 'REQUEST_CANCELLED', '请求已取消。请刷新方案详情确认提交结果。');
    if (timeout.aborted) return proxyError(504, 'UPSTREAM_TIMEOUT', '提交结果未知。请刷新方案详情确认，勿直接重复提交。');
    return proxyError(503, 'RESPONSES_UNAVAILABLE', '提交结果未知。请刷新方案详情确认，勿直接重复提交。');
  }
}

export async function proxyRenewal(request: Request, planId: string): Promise<Response> {
  if (!validPlanId(planId)) return proxyError(400, 'INVALID_PLAN_ID', '响应方案编号无效。');
  const configuredOrigin = process.env.FRONTEND_ORIGIN?.trim() || 'http://127.0.0.1:3000';
  const origin = request.headers.get('origin');
  try {
    if (!origin || origin !== configuredOrigin || request.headers.get('host') !== new URL(configuredOrigin).host) {
      return proxyError(403, 'CROSS_ORIGIN_REQUEST', '不接受跨站续办请求。');
    }
  } catch {
    return proxyError(403, 'CROSS_ORIGIN_REQUEST', '不接受跨站续办请求。');
  }
  if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return proxyError(415, 'UNSUPPORTED_MEDIA_TYPE', '续办请求必须使用 JSON。');
  }
  const sessionCookies = (request.headers.get('cookie') ?? '').split(';').map((cookie) => cookie.trim())
    .filter((cookie) => cookie.startsWith('evidencesoc_demo_session='));
  if (sessionCookies.length !== 1 || sessionCookies[0].length === 'evidencesoc_demo_session='.length) {
    return proxyError(401, 'SESSION_REQUIRED', '请先启用本地演示会话。');
  }
  const idempotencyKey = request.headers.get('idempotency-key');
  if (!idempotencyKey || !/^[\x21-\x7e]{1,255}$/.test(idempotencyKey)) {
    return proxyError(400, 'INVALID_IDEMPOTENCY_KEY', '提交标识无效。');
  }
  let input: unknown;
  try {
    const raw = await request.text();
    if (raw.length > 4096) return proxyError(400, 'INVALID_REQUEST', '请求数据无效。');
    input = JSON.parse(raw);
  } catch {
    return proxyError(400, 'INVALID_REQUEST', '请求数据无效。');
  }
  if (input === null || typeof input !== 'object' || Array.isArray(input)
    || Object.keys(input).length !== 1 || !Object.hasOwn(input, 'plan_version')
    || typeof (input as { plan_version?: unknown }).plan_version !== 'string'
    || !/^[a-f0-9]{64}$/.test((input as { plan_version: string }).plan_version)) {
    return proxyError(400, 'INVALID_REQUEST', '方案版本无效。');
  }
  const timeout = AbortSignal.timeout(20_000);
  try {
    const upstream = backendUrl(`/api/v1/response-plans/${encodeURIComponent(planId)}/renew`);
    const response = await fetch(upstream, {
      method: 'POST', cache: 'no-store', redirect: 'manual',
      headers: {
        Accept: 'application/json', 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey,
        Origin: origin, Cookie: sessionCookies[0],
      },
      body: JSON.stringify(input),
      signal: AbortSignal.any([request.signal, timeout]),
    });
    return forwardResponse(response, await response.text());
  } catch {
    if (request.signal.aborted) return proxyError(499, 'REQUEST_CANCELLED', '续办请求已取消。请刷新方案详情确认结果。');
    if (timeout.aborted) return proxyError(504, 'UPSTREAM_TIMEOUT', '续办结果未知。请刷新方案详情确认，勿直接重复提交。');
    return proxyError(503, 'RESPONSES_UNAVAILABLE', '续办结果未知。请刷新方案详情确认，勿直接重复提交。');
  }
}
