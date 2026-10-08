import { afterEach, expect, it, vi } from 'vitest';
import { GET } from './route';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

function request(cookie = 'evidencesoc_demo_session=valid-token; analytics=private') {
  return new Request('http://web.test/api/v1/incidents/IN-123/evidence/EV-01K5TESTTESTTESTTESTTESTTEST?url=http://evil.test', {
    headers: { Cookie: cookie },
  });
}

function context(id = 'IN-123', evidenceId = 'EV-01K5TESTTESTTESTTESTTESTTEST') {
  return { params: Promise.resolve({ id, evidenceId }) };
}

it('uses the fixed authorized evidence path and does not forward arbitrary query', async () => {
  vi.stubEnv('BACKEND_URL', 'http://backend.test:8000/ignored-prefix');
  const upstream = vi.fn().mockResolvedValue(new Response(JSON.stringify({ evidence: { evidence_id: 'EV-1' } }), {
    status: 200, headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-evidence' },
  }));
  vi.stubGlobal('fetch', upstream);
  const response = await GET(request(), context());
  const [target, options] = upstream.mock.calls[0];
  expect(String(target)).toBe('http://backend.test:8000/api/v1/incidents/IN-123/evidence/EV-01K5TESTTESTTESTTESTTESTTEST');
  expect(options).toMatchObject({ cache: 'no-store', redirect: 'manual' });
  expect(new Headers(options.headers).get('Cookie')).toBe('evidencesoc_demo_session=valid-token');
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(response.headers.get('x-trace-id')).toBe('TRACE-evidence');
});

it('拒绝无专用会话 Cookie 且不会请求后端原文', async () => {
  const upstream = vi.fn(); vi.stubGlobal('fetch', upstream);
  const response = await GET(request('analytics=private'), context());
  expect(response.status).toBe(401);
  expect(upstream).not.toHaveBeenCalled();
});

it('passes through scoped 404 and trace without substituting another evidence', async () => {
  const error = { error: { code: 'NOT_FOUND', message: 'evidence not found', trace_id: 'TRACE-404' } };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(error), {
    status: 404, headers: { 'content-type': 'application/json', 'x-trace-id': 'TRACE-404' },
  })));
  const response = await GET(request(), context());
  expect(response.status).toBe(404);
  expect(response.headers.get('x-trace-id')).toBe('TRACE-404');
  expect(await response.json()).toEqual(error);
});

it('rejects malformed incident or evidence ids before calling backend', async () => {
  const upstream = vi.fn(); vi.stubGlobal('fetch', upstream);
  expect((await GET(request(), context('../alerts'))).status).toBe(400);
  expect((await GET(request(), context('IN-123', '../other'))).status).toBe(400);
  expect(upstream).not.toHaveBeenCalled();
});
