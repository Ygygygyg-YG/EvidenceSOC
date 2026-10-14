import { expect, test } from '@playwright/test';

test('同源会话代理签发 HttpOnly 演示 cookie，并由真实后端确认身份', async ({ page }) => {
  let loginHeaders: Record<string, string> = {};
  await page.route('**/api/v1/session/demo', async (route) => {
    loginHeaders = route.request().headers();
    await route.continue();
  });
  await page.goto('/responses');
  const result = await page.evaluate(async () => {
    const before = await fetch('/api/v1/session', { cache: 'no-store' });
    const login = await fetch('/api/v1/session/demo', { method: 'POST' });
    const loginBody = await login.json();
    const after = await fetch('/api/v1/session', { cache: 'no-store' });
    const decision = await fetch('/api/v1/response-plans/RP-no-such-plan/approve', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': crypto.randomUUID() },
      body: JSON.stringify({ plan_version: 'a'.repeat(64), reason: '只验证代理边界' }),
    });
    return { before: before.status, login: login.status, loginBody, actor: loginBody.actor_id,
      after: after.status, session: await after.json(), decisionStatus: decision.status,
      decisionError: await decision.json() };
  });
  expect(result.before).toBe(401);
  expect(result.login, JSON.stringify({ body: result.loginBody, headers: loginHeaders })).toBe(200);
  expect(result.actor).toBe('demo-reviewer');
  expect(result.after).toBe(200);
  expect(result.session).toMatchObject({
    actor_id: 'demo-reviewer', role: 'reviewer', allowed_actions: ['approve', 'reject'],
  });
  expect(result.decisionStatus, JSON.stringify(result.decisionError)).toBe(404);
  const cookies = await page.context().cookies('http://127.0.0.1:3000');
  expect(cookies).toEqual(expect.arrayContaining([expect.objectContaining({
    name: 'evidencesoc_demo_session', httpOnly: true, sameSite: 'Strict', path: '/',
  })]));
});
