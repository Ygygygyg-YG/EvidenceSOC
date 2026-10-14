import { randomUUID } from 'node:crypto';

const cookieName = 'evidencesoc_demo_session';

function errorResponse(status: number, code: string, message: string): Response {
  const traceId = `WEB-${randomUUID()}`;
  return Response.json({ error: { code, message, trace_id: traceId } }, {
    status, headers: { 'Cache-Control': 'no-store', 'x-trace-id': traceId },
  });
}

function backendUrl(): URL {
  const backend = process.env.BACKEND_URL?.trim() || 'http://127.0.0.1:8000';
  const url = new URL('/api/v1/session', backend);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Unsupported backend URL');
  return url;
}

function sessionCookie(request: Request): string | null {
  const matches = (request.headers.get('cookie') ?? '').split(';').map((part) => part.trim())
    .filter((part) => part.startsWith(`${cookieName}=`));
  return matches.length === 1 && matches[0].length > cookieName.length + 1 ? matches[0] : null;
}

function forward(response: Response, body: string, setCookie?: string): Response {
  const headers = new Headers({
    'Content-Type': response.headers.get('content-type') || 'application/json',
    'Cache-Control': 'no-store',
  });
  const traceId = response.headers.get('x-trace-id');
  if (traceId) headers.set('x-trace-id', traceId);
  if (setCookie) headers.set('set-cookie', setCookie);
  return new Response(body, { status: response.status, headers });
}

function failedProxy(request: Request, timeout: AbortSignal): Response {
  if (request.signal.aborted) return errorResponse(499, 'REQUEST_CANCELLED', '会话请求已取消。');
  if (timeout.aborted) return errorResponse(504, 'UPSTREAM_TIMEOUT', '会话服务超时，请重试。');
  return errorResponse(503, 'SESSION_UNAVAILABLE', '会话服务暂时不可用，请重试。');
}

export async function proxySessionGet(request: Request): Promise<Response> {
  const cookie = sessionCookie(request);
  if (!cookie) return errorResponse(401, 'SESSION_REQUIRED', '请先启用本地演示会话。');
  const timeout = AbortSignal.timeout(10_000);
  try {
    const response = await fetch(backendUrl(), {
      cache: 'no-store', redirect: 'manual', headers: { Accept: 'application/json', Cookie: cookie },
      signal: AbortSignal.any([request.signal, timeout]),
    });
    return forward(response, await response.text());
  } catch {
    return failedProxy(request, timeout);
  }
}

export async function proxyDemoSessionPost(request: Request): Promise<Response> {
  const configuredOrigin = process.env.FRONTEND_ORIGIN?.trim() || 'http://127.0.0.1:3000';
  const origin = request.headers.get('origin');
  if (!origin || origin !== configuredOrigin || request.headers.get('host') !== new URL(configuredOrigin).host) {
    return errorResponse(403, 'CROSS_ORIGIN_REQUEST', '不接受跨站会话请求。');
  }
  if (request.body !== null) {
    try {
      const reader = request.body.getReader();
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        if (chunk.value.byteLength > 0) {
          await reader.cancel();
          return errorResponse(400, 'INVALID_REQUEST', '启用会话不接受请求正文。');
        }
      }
    } catch {
      return errorResponse(400, 'INVALID_REQUEST', '无法读取会话请求。');
    }
  }
  const timeout = AbortSignal.timeout(10_000);
  try {
    const response = await fetch(new URL('/api/v1/session/demo', backendUrl()), {
      method: 'POST', cache: 'no-store', redirect: 'manual',
      headers: { Accept: 'application/json', Origin: origin },
      signal: AbortSignal.any([request.signal, timeout]),
    });
    const body = await response.text();
    if (!response.ok) return forward(response, body);
    const cookie = response.headers.get('set-cookie');
    if (!cookie || !cookie.startsWith(`${cookieName}=`)
      || !/;\s*httponly(?:;|$)/i.test(cookie) || !/;\s*samesite=strict(?:;|$)/i.test(cookie)) {
      return errorResponse(502, 'INVALID_SESSION_RESPONSE', '会话服务未返回安全 Cookie。');
    }
    return forward(response, body, cookie);
  } catch {
    return failedProxy(request, timeout);
  }
}
