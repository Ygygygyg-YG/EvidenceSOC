import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import type { components } from '../src/lib/api/generated';

type Snapshot = components['schemas']['InvestigationSnapshot'];
type Plan = components['schemas']['ResponsePlanDetail'];
type Observed = { event: string; id: string; data: Record<string, unknown> };
declare global {
  interface Window {
    renewalObserver: { source: EventSource; opened: boolean; events: Observed[]; resets: unknown[] };
  }
}
type ObserverWindow = Window;

function environment() {
  const required = ['TASK10_LIVE_ISOLATED_BACKEND', 'TASK10_LIVE_SEED_ALERT_ID',
    'TASK10_ACCEPTANCE_RUN_ID', 'TASK10_ACCEPTANCE_ROOT', 'TASK10_ACCEPTANCE_PYTHON'] as const;
  for (const key of required) expect(process.env[key], `${key} is required; missing live setup is a failure`).toBeTruthy();
  expect(process.env.BACKEND_URL).toBe(process.env.TASK10_LIVE_ISOLATED_BACKEND);
  expect(new URL(process.env.BACKEND_URL!).hostname).toBe('127.0.0.1');
  return {
    backend: process.env.BACKEND_URL!, seed: process.env.TASK10_LIVE_SEED_ALERT_ID!,
    runId: process.env.TASK10_ACCEPTANCE_RUN_ID!, root: process.env.TASK10_ACCEPTANCE_ROOT!,
    python: process.env.TASK10_ACCEPTANCE_PYTHON!,
  };
}

async function observe(page: Page, investigationId: string, cursor: string) {
  await page.evaluate(({ investigationId, cursor }) => {
    const target = window as ObserverWindow;
    target.renewalObserver?.source.close();
    const source = new EventSource(`/api/v1/investigations/${encodeURIComponent(investigationId)}/stream?cursor=${encodeURIComponent(cursor)}`);
    const observer = { source, opened: false, events: [] as Observed[], resets: [] as unknown[] };
    target.renewalObserver = observer;
    source.onopen = () => { observer.opened = true; };
    for (const name of ['status', 'approval.required', 'decision.recorded', 'validation.completed', 'investigation.completed']) {
      source.addEventListener(name, (event) => {
        const message = event as MessageEvent;
        observer.events.push({ event: name, id: message.lastEventId, data: JSON.parse(message.data) });
      });
    }
    source.addEventListener('stream.reset', (event) => { observer.resets.push(JSON.parse((event as MessageEvent).data)); });
  }, { investigationId, cursor });
  // An idle stream may flush its first body bytes with the 15-second SSE heartbeat.
  await expect.poll(() => page.evaluate(() => (window as ObserverWindow).renewalObserver.opened), { timeout: 20_000 }).toBe(true);
}

test('真实过期方案续办经原生 SSE 返回新方案，再经页面批准和验证', async ({ page, request, context, baseURL }, info) => {
  test.setTimeout(180_000);
  const env = environment();
  const seedResponse = await request.get(`${env.backend}/api/v1/alerts/${encodeURIComponent(env.seed)}`);
  expect(seedResponse.ok()).toBe(true);
  const seed = await seedResponse.json();
  const suffix = randomUUID().slice(0, 8);
  const alertId = `AL-RENEW-${env.runId}-${suffix}`;
  const created = await request.post(`${env.backend}/api/v1/alerts`, {
    headers: { 'Idempotency-Key': `renewal-alert-${env.runId}-${suffix}` },
    data: { alert_id: alertId, title: `真实续办 ${suffix}`, severity: 'high', created_at: seed.created_at, event_ids: seed.event_ids },
  });
  expect(created.status()).toBe(201);
  const origin = new URL(baseURL!).origin;
  expect((await page.request.post('/api/v1/session/demo', { headers: { Origin: origin } })).ok()).toBe(true);
  await page.goto(`/alerts/${alertId}`);
  const started = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/v1/investigations');
  await page.getByRole('button', { name: '启动调查', exact: true }).click();
  const accepted = await started;
  expect(accepted.status()).toBe(202);
  const investigation = await accepted.json();
  const snapshot = async (): Promise<Snapshot> => {
    const response = await request.get(`${env.backend}/api/v1/investigations/${investigation.investigation_id}`);
    expect(response.ok()).toBe(true);
    return await response.json();
  };
  await expect.poll(async () => (await snapshot()).status, { timeout: 60_000 }).toBe('awaiting_approval');
  const pending = await snapshot();
  const oldId = pending.response_plan!.response_plan_id;
  execFileSync(env.python, [path.join(env.root, 'scripts/task10_browser_acceptance.py'), '--root', env.root,
    '--expire-plan-id', oldId, '--run-id', env.runId], { cwd: env.root, env: process.env, timeout: 30_000 });
  const oldResponse = await page.request.get(`/api/v1/response-plans/${oldId}`);
  const old = await oldResponse.json() as Plan;
  expect(old.is_expired).toBe(true);
  await page.goto(`/responses/${oldId}`);
  await expect(page.getByRole('button', { name: '重新生成方案', exact: true })).toBeVisible();

  const incidentPage = await context.newPage();
  await incidentPage.goto(`/incidents/${investigation.incident_id}`);
  await observe(incidentPage, investigation.investigation_id, pending.stream_cursor);
  let renewalPosts = 0;
  page.on('request', (req) => { if (req.method() === 'POST' && new URL(req.url()).pathname.endsWith(`/${oldId}/renew`)) renewalPosts++; });
  const renewalResponse = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith(`/${oldId}/renew`));
  await page.getByRole('button', { name: '重新生成方案', exact: true }).click();
  expect((await renewalResponse).status()).toBe(202);
  await expect.poll(async () => (await snapshot()).response_plan?.response_plan_id, { timeout: 60_000 }).not.toBe(oldId);
  await expect.poll(async () => (await snapshot()).status).toBe('awaiting_approval');
  const renewed = await snapshot();
  const newId = renewed.response_plan!.response_plan_id;
  expect(newId).not.toBe(oldId);
  await expect.poll(() => incidentPage.evaluate(() => (window as ObserverWindow).renewalObserver.events
    .some((item) => item.event === 'approval.required'))).toBe(true);
  const events = await incidentPage.evaluate(() => (window as ObserverWindow).renewalObserver.events);
  expect(events.some((item) => item.event === 'status' && item.data.status === 'reconstructing')).toBe(true);
  const ready = events.find((item) => item.event === 'approval.required');
  expect(ready!.data.response_plan).toMatchObject({ response_plan_id: newId });
  expect(events.findIndex((item) => item.event === 'status')).toBeLessThan(events.indexOf(ready!));
  expect(await incidentPage.evaluate(() => (window as ObserverWindow).renewalObserver.resets)).toEqual([]);
  expect(renewalPosts).toBe(1);
  await expect(incidentPage.getByRole('link', { name: /查看响应方案/ })).toHaveAttribute('href', `/responses/${newId}`);
  const previous = await (await page.request.get(`/api/v1/response-plans/${oldId}`)).json() as Plan;
  const fresh = await (await page.request.get(`/api/v1/response-plans/${newId}`)).json() as Plan;
  expect(previous.is_current).toBe(false);
  expect(previous.available_actions).toEqual([]);
  expect(fresh).toMatchObject({ is_current: true, is_expired: false, approval: null, simulation: [] });
  expect(fresh.plan_version).not.toBe(old.plan_version);
  expect(fresh.evidence_ids).toEqual(old.evidence_ids);

  // Close a real connection, then resume from the last received public cursor.
  const resumeCursor = ready!.id;
  await observe(incidentPage, investigation.investigation_id, resumeCursor);
  await page.goto(`/responses/${newId}`);
  await page.getByRole('textbox', { name: '决定理由' }).fill('已核对续办后的新方案及原始证据');
  await page.getByRole('button', { name: '批准方案', exact: true }).click();
  await page.getByRole('button', { name: '确认提交批准', exact: true }).click();
  await expect(page.getByRole('heading', { name: '验证成功', exact: true })).toBeVisible({ timeout: 60_000 });
  await expect.poll(async () => (await snapshot()).status).toBe('completed');
  await expect.poll(() => incidentPage.evaluate(() => (window as ObserverWindow).renewalObserver.events
    .some((item) => item.event === 'investigation.completed'))).toBe(true);
  const resumed = await incidentPage.evaluate(() => (window as ObserverWindow).renewalObserver.events);
  expect(resumed.every((item) => BigInt(item.id) > BigInt(resumeCursor))).toBe(true);
  expect(new Set(resumed.map((item) => item.id)).size).toBe(resumed.length);
  expect(await incidentPage.evaluate(() => (window as ObserverWindow).renewalObserver.resets)).toEqual([]);
  await incidentPage.evaluate(() => (window as ObserverWindow).renewalObserver.source.close());
  const final = await snapshot();
  expect(final.approval).toMatchObject({ decision: 'approved', response_plan_id: newId });
  expect(final.validation_result).toMatchObject({ outcome: 'success', response_plan_id: newId });
  await page.reload();
  await expect(page.getByRole('heading', { name: '验证成功', exact: true })).toBeVisible();
  await info.attach('renewal-live-flow.json', { contentType: 'application/json',
    body: JSON.stringify({ runId: env.runId, alertId, investigationId: investigation.investigation_id,
      oldPlanId: oldId, newPlanId: newId, renewalPosts, events, resumeCursor, resumed, snapshot: final }, null, 2) });
});
