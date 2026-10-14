import { z } from 'zod';
import { ResponsePlanRequestError } from './responseContract';

export const demoSessionSchema = z.object({
  actor_id: z.literal('demo-reviewer'),
  role: z.literal('reviewer'),
  allowed_actions: z.array(z.enum(['approve', 'reject'])),
  expires_at: z.iso.datetime({ offset: true }),
}).superRefine((session, context) => {
  if (new Set(session.allowed_actions).size !== session.allowed_actions.length) {
    context.addIssue({ code: 'custom', message: '会话权限重复。' });
  }
});
export type DemoSession = z.infer<typeof demoSessionSchema>;

const errorEnvelope = z.object({ error: z.object({
  code: z.string(), message: z.string(), trace_id: z.string().nullable(),
}) });

async function requestSession(path: string, method: 'GET' | 'POST'): Promise<DemoSession | null> {
  let response: Response;
  try {
    response = await fetch(path, {
      method, cache: 'no-store', headers: { Accept: 'application/json' },
    });
  } catch {
    throw new ResponsePlanRequestError('NETWORK_ERROR', '无法连接会话服务，请重试。');
  }
  if (method === 'GET' && response.status === 401) return null;
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new ResponsePlanRequestError('INVALID_RESPONSE', '会话服务返回了无法读取的数据。', response.headers.get('x-trace-id') || undefined, response.status); }
  if (!response.ok) {
    const parsed = errorEnvelope.safeParse(body);
    if (parsed.success) throw new ResponsePlanRequestError(
      parsed.data.error.code, parsed.data.error.message,
      parsed.data.error.trace_id || response.headers.get('x-trace-id') || undefined, response.status,
    );
    throw new ResponsePlanRequestError('HTTP_ERROR', `会话请求失败（HTTP ${response.status}）。`, response.headers.get('x-trace-id') || undefined, response.status);
  }
  const parsed = demoSessionSchema.safeParse(body);
  if (!parsed.success) throw new ResponsePlanRequestError('INVALID_RESPONSE', '会话信息不符合接口契约。', response.headers.get('x-trace-id') || undefined, response.status);
  return parsed.data;
}

export async function loadDemoSession(): Promise<DemoSession | null> {
  return requestSession('/api/v1/session', 'GET');
}

export async function startDemoSession(): Promise<DemoSession> {
  const session = await requestSession('/api/v1/session/demo', 'POST');
  if (!session) throw new ResponsePlanRequestError('INVALID_RESPONSE', '演示会话未建立。');
  return session;
}
