import { afterEach, expect, it, vi } from 'vitest';
import { demoSessionSchema, loadDemoSession, startDemoSession } from './sessionContract';

const session = {
  actor_id: 'demo-reviewer', role: 'reviewer', allowed_actions: ['approve', 'reject'],
  expires_at: '2026-10-01T06:30:00Z',
};

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it('只接受服务端返回的有效演示会话', () => {
  expect(demoSessionSchema.parse(session)).toEqual(session);
  expect(demoSessionSchema.safeParse({ ...session, role: 'administrator' }).success).toBe(false);
  expect(demoSessionSchema.safeParse({ ...session, allowed_actions: ['delete_all'] }).success).toBe(false);
});

it('GET 会话时 401 表示未登录；其他服务错误不冒充未登录', async () => {
  const mockedFetch = vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'SESSION_REQUIRED', message: '未登录', trace_id: 'TRACE-1' } }), { status: 401 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'OFFLINE', message: '服务不可用', trace_id: 'TRACE-2' } }), { status: 503 }));
  vi.stubGlobal('fetch', mockedFetch);
  expect(await loadDemoSession()).toBeNull();
  await expect(loadDemoSession()).rejects.toMatchObject({ code: 'OFFLINE', status: 503, traceId: 'TRACE-2' });
  expect(mockedFetch.mock.calls[0][0]).toBe('/api/v1/session');
});

it('显式启用本地演示会话，并检查返回身份', async () => {
  const mockedFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(session)));
  vi.stubGlobal('fetch', mockedFetch);
  expect(await startDemoSession()).toEqual(session);
  expect(mockedFetch).toHaveBeenCalledTimes(1);
  expect(mockedFetch.mock.calls[0][0]).toBe('/api/v1/session/demo');
  expect(mockedFetch.mock.calls[0][1].method).toBe('POST');
  expect(mockedFetch.mock.calls[0][1].body).toBeUndefined();
});
