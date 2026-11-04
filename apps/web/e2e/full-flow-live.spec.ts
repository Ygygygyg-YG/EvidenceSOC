import { createHash, randomUUID } from 'node:crypto';
import { expect, test, type APIRequestContext, type Page, type TestInfo } from '@playwright/test';
import type { components } from '../src/lib/api/generated';

type Snapshot = components['schemas']['InvestigationSnapshot'];
type Plan = components['schemas']['ResponsePlanDetail'];
type EvidenceDetail = components['schemas']['EvidenceDetail'];
type Investigation = components['schemas']['InvestigationAccepted'];

const viewports = [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }];
const investigationRoles = ['triage', 'collect', 'analyze', 'reconstruct', 'respond'];

function liveEnvironment() {
  const seedAlertId = process.env.TASK10_LIVE_SEED_ALERT_ID;
  const isolatedBackend = process.env.TASK10_LIVE_ISOLATED_BACKEND;
  // A skipped real-service test is not an acceptance result.
  expect(seedAlertId, 'TASK10_LIVE_SEED_ALERT_ID must identify the imported sample').toBeTruthy();
  expect(isolatedBackend, 'TASK10_LIVE_ISOLATED_BACKEND must identify an isolated backend').toBeTruthy();
  expect(process.env.BACKEND_URL, 'Web proxy and direct API checks must use the same backend').toBe(isolatedBackend);
  const backend = new URL(isolatedBackend!);
  expect(['127.0.0.1', 'localhost', '[::1]']).toContain(backend.hostname);
  return { seedAlertId: seedAlertId!, backend };
}

async function readJson<T>(request: APIRequestContext, url: string): Promise<T> {
  const response = await request.get(url);
  expect(response.ok(), `${response.status()} ${await response.text()}`).toBe(true);
  return await response.json() as T;
}

async function snapshot(request: APIRequestContext, investigationId: string): Promise<Snapshot> {
  const { backend } = liveEnvironment();
  return readJson(request, new URL(`/api/v1/investigations/${investigationId}`, backend).toString());
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(',')}}`;
  }
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new Error('Raw event contains non-JSON data');
  return serialized;
}

async function checkViewports(page: Page, info: TestInfo, checkpoint: string) {
  for (const viewport of viewports) {
    await page.setViewportSize(viewport);
    await expect.poll(() => page.evaluate(() => Math.max(
      document.documentElement.scrollWidth, document.body.scrollWidth,
    ) - window.innerWidth), { message: `${checkpoint}: no page overflow at ${viewport.width}×${viewport.height}` })
      .toBeLessThanOrEqual(1);
    await info.attach(`${checkpoint}-${viewport.width}x${viewport.height}`, {
      body: await page.screenshot({ fullPage: true }), contentType: 'image/png',
    });
  }
}

function assertCompletedRoles(state: Snapshot, roles: string[]) {
  for (const role of roles) {
    const runs = state.runs.filter((run) => run.agent_name === role);
    expect(runs.length, `${role} must have a persisted run`).toBeGreaterThan(0);
    expect(runs.at(-1)?.status, `${role} must complete`).toBe('completed');
    expect(runs.at(-1)?.finished_at).not.toBeNull();
  }
}

async function inspectEvidence(page: Page, info: TestInfo, state: Snapshot) {
  const node = state.attack_graph.nodes.find((item) => item.evidence_ids.length > 0);
  expect(node, 'The real attack graph must cite collected evidence').toBeTruthy();
  const evidenceId = node!.evidence_ids[0];
  const cited = state.evidence.find((item) => item.evidence_id === evidenceId);
  expect(cited).toBeTruthy();
  expect(state.alert.event_ids).toContain(cited!.event_id);
  expect(Object.keys(cited!.query).length).toBeGreaterThan(0);
  const detail = await readJson<EvidenceDetail>(page.request,
    `/api/v1/incidents/${state.incident_id}/evidence/${evidenceId}`);
  expect(detail.evidence).toMatchObject(cited!);
  expect(detail.raw_event.event_id).toBe(cited!.event_id);
  expect(detail.raw_event.source).toBe(cited!.source);
  expect(detail.raw_event.observed_at).toBe(cited!.observed_at);
  expect(detail.raw_access).toBe('full');
  const calculated = createHash('sha256').update(canonicalJson(detail.raw_event.raw), 'utf8').digest('hex');
  expect(detail.integrity).toMatchObject({
    algorithm: 'sha256', canonicalization: 'evidencesoc-json-v1', scope: 'postgresql', status: 'verified',
    calculated_sha256: calculated, stored_event_sha256: calculated, stored_evidence_sha256: calculated,
  });
  expect(cited!.content_sha256).toBe(calculated);
  expect(detail.raw_event.content_sha256).toBe(calculated);

  for (const viewport of viewports) {
    await page.setViewportSize(viewport);
    const card = page.getByTestId('attack-graph').getByRole('button', {
      name: `第 ${node!.sequence} 步 ${node!.description}`, exact: true,
    });
    await expect(card).toBeVisible();
    await expect(card).toContainText(node!.phase ?? '阶段未提供');
    await expect(card).toContainText(node!.host ?? '主机未提供');
    await expect(card).toContainText(node!.confidence === null ? '置信度未提供' : `${Math.round(node!.confidence * 100)}%`);
    if (node!.observed_at) await expect(card.locator('time')).toHaveAttribute('datetime', node!.observed_at);
    await card.click();
    const inspector = page.getByRole('region', { name: '证据检查器' });
    await expect(inspector).toContainText(`第 ${node!.sequence} 步引用的证据`);
    await inspector.locator('ul button').filter({ hasText: evidenceId }).click();
    await expect(inspector.getByText('PostgreSQL 本次校验通过')).toBeVisible();
    await expect(inspector).toContainText(cited!.source);
    await expect(inspector).toContainText(cited!.event_id);
    const displayed = await inspector.locator('pre').allTextContents();
    expect(displayed.map((text) => { try { return JSON.parse(text); } catch { return null; } }))
      .toEqual(expect.arrayContaining([detail.raw_event.raw, cited!.query]));
    expect(displayed.filter((text) => text === calculated).length).toBeGreaterThanOrEqual(4);
    expect(await page.evaluate(() => Math.max(document.documentElement.scrollWidth,
      document.body.scrollWidth) - window.innerWidth), 'Open evidence inspector must fit the viewport')
      .toBeLessThanOrEqual(1);
    await info.attach(`evidence-${viewport.width}x${viewport.height}`, {
      body: await page.screenshot({ fullPage: true }), contentType: 'image/png',
    });
    const drawer = page.getByRole('dialog', { name: '证据检查器' });
    if (await drawer.isVisible()) {
      await drawer.getByRole('button', { name: '关闭', exact: true }).click();
      await expect(drawer).toBeHidden();
    }
  }
  await info.attach('verified-evidence.json', { body: JSON.stringify(detail, null, 2), contentType: 'application/json' });
}

async function startCase(page: Page, request: APIRequestContext, info: TestInfo, decision: 'approve' | 'reject') {
  const { seedAlertId, backend } = liveEnvironment();
  const seed = await readJson<components['schemas']['Alert']>(request,
    new URL(`/api/v1/alerts/${seedAlertId}`, backend).toString());
  expect(seed.event_ids.length).toBeGreaterThan(0);
  const suffix = randomUUID();
  const alertId = `AL-TASK12-LIVE-${decision.toUpperCase()}-${suffix}`;
  const title = `Task12 真实${decision === 'approve' ? '批准' : '拒绝'}闭环 ${suffix}`;
  const created = await request.post(new URL('/api/v1/alerts', backend).toString(), {
    headers: { 'Idempotency-Key': `task12-live-${decision}-${suffix}` },
    data: { alert_id: alertId, title, severity: 'high', created_at: seed.created_at, event_ids: seed.event_ids },
  });
  expect(created.status(), await created.text()).toBe(201);

  // Authenticate through the real proxy before navigation so expected anonymous
  // 401s do not obscure the strict browser console-error assertion.
  const origin = new URL(info.project.use.baseURL!).origin;
  const session = await page.request.post('/api/v1/session/demo', { headers: { Origin: origin } });
  expect(session.ok(), await session.text()).toBe(true);
  expect((await session.json()).actor_id).toBe('demo-reviewer');
  await page.setViewportSize(viewports[0]);
  await page.goto(`/alerts?query=${encodeURIComponent(title)}`);
  const alertLink = page.getByRole('table', { name: '告警记录' }).getByRole('link', { name: title });
  await expect(alertLink).toBeVisible();
  await checkViewports(page, info, 'alert-list');
  await alertLink.click();
  await expect(page.getByRole('heading', { name: title, level: 1 })).toBeVisible();
  await expect(page.getByText('demo-reviewer')).toBeVisible();
  const startedResponse = page.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/v1/investigations' && response.request().method() === 'POST');
  await page.getByRole('button', { name: '启动调查', exact: true }).click();
  const response = await startedResponse;
  expect(response.status(), await response.text()).toBe(202);
  const investigation = await response.json() as Investigation;
  await expect(page).toHaveURL(new RegExp(`/incidents/${investigation.incident_id}$`));
  const progress = page.getByRole('region', { name: '六角色进度' });
  await expect(progress.locator('ol > li')).toHaveCount(6);
  await expect(page.getByRole('link', { name: /查看响应方案/ })).toBeVisible({ timeout: 60_000 });
  await expect.poll(async () => (await snapshot(request, investigation.investigation_id)).status,
    { timeout: 60_000 }).toBe('awaiting_approval');
  const pending = await snapshot(request, investigation.investigation_id);
  expect(pending.status).toBe('awaiting_approval');
  expect(pending.alert.alert_id).toBe(alertId);
  expect(pending.mode).toBe('rules');
  assertCompletedRoles(pending, investigationRoles);
  expect(pending.runs.some((run) => run.agent_name === 'validate')).toBe(false);
  await expect(progress.getByText('等待批准后执行')).toBeVisible();
  expect(pending.response_plan).not.toBeNull();
  await inspectEvidence(page, info, pending);
  await checkViewports(page, info, 'incident-awaiting-approval');

  const planId = pending.response_plan!.response_plan_id;
  await page.getByRole('link', { name: /查看响应方案/ }).click();
  await expect(page).toHaveURL(new RegExp(`/responses/${planId}$`));
  await expect(page.getByRole('heading', { name: '人工决定' })).toBeVisible();
  await expect(page.getByText('demo-reviewer')).toBeVisible();
  const plan = await readJson<Plan>(request, new URL(`/api/v1/response-plans/${planId}`, backend).toString());
  expect(plan.incident_id).toBe(investigation.incident_id);
  expect(plan.available_actions).toEqual(expect.arrayContaining(['approve', 'reject']));
  await checkViewports(page, info, 'response-pending');
  return { alertId, origin, investigation, plan };
}

function assertRejected(state: Snapshot) {
  expect(state.status).toBe('rejected');
  expect(state.incident.status).toBe('rejected');
  assertCompletedRoles(state, investigationRoles);
  expect(state.runs.some((run) => run.agent_name === 'validate')).toBe(false);
  expect(state.simulation).toEqual([]);
  expect(state.simulation_execution).toBeNull();
  expect(state.validation_result).toBeNull();
  expect(state.validation).toBeNull();
  expect(state.available_actions).toEqual([]);
}

test.beforeAll(() => { liveEnvironment(); });

for (const action of ['approve', 'reject'] as const) {
  test(`真实规则调查经页面完成证据核验、人工${action === 'approve' ? '批准与模拟验证' : '拒绝并停止处置'}`, async ({ page, request }, info) => {
    test.setTimeout(180_000);
    const errors: string[] = [];
    page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });
    page.on('pageerror', (error) => errors.push(error.message));
    const context = await startCase(page, request, info, action);
    const reason = action === 'approve' ? '已核对原始证据、模拟影响与回滚计划' : '原始证据已核验；当前业务影响不可接受，拒绝模拟处置';
    await page.getByRole('textbox', { name: '决定理由' }).fill(reason);
    await page.getByRole('button', { name: action === 'approve' ? '批准方案' : '拒绝方案' }).click();
    await page.getByRole('button', { name: action === 'approve' ? '确认提交批准' : '确认提交拒绝' }).click();
    await expect(page.getByRole('heading', { name: '已记录的审批' })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByRole('complementary', { name: '人工决定' }).getByText(reason, { exact: true })).toBeVisible();
    if (action === 'approve') await expect(page.getByRole('heading', { name: '证据不足' })).toBeVisible({ timeout: 60_000 });
    await expect.poll(async () => (await snapshot(request, context.investigation.investigation_id)).status)
      .toBe(action === 'approve' ? 'manual_review' : 'rejected');
    const final = await snapshot(request, context.investigation.investigation_id);
    expect(final.approval).toMatchObject({ decision: action === 'approve' ? 'approved' : 'rejected', reason,
      decided_by: 'demo-reviewer', response_plan_id: context.plan.response_plan_id });
    expect(final.available_actions).toEqual([]);
    if (action === 'approve') {
      assertCompletedRoles(final, [...investigationRoles, 'validate']);
      expect(final.simulation.length).toBeGreaterThan(0);
      expect(final.simulation.every((result) => result.simulated === true && result.status === 'simulated')).toBe(true);
      expect(final.simulation_execution).toMatchObject({ status: 'completed', response_plan_id: context.plan.response_plan_id,
        plan_version: context.plan.plan_version, error: null });
      expect(final.simulation_execution!.action_results.length).toBe(context.plan.actions.length);
      expect(final.simulation_execution!.action_results.map((result) => result.action_id).sort())
        .toEqual(context.plan.actions.map((item) => item.action_id).sort());
      expect(final.simulation_execution!.action_results.every((result) => result.outcome === 'success')).toBe(true);
      expect(final.validation_result).toMatchObject({ outcome: 'insufficient_evidence', response_plan_id: context.plan.response_plan_id });
      expect(final.status).toBe('manual_review');
      expect(final.stop_reason).toBe('insufficient_evidence');
      expect(final.errors).toEqual([]);
      expect(final.validation_result!.summary).toContain('unverified');
      expect(final.validation_result!.checks?.every((check) => check.outcome === 'insufficient_evidence')).toBe(true);
      await expect(page.getByRole('heading', { name: '验证成功', exact: true })).toHaveCount(0);
      expect(final.validation_result!.evidence_ids.length).toBeGreaterThan(0);
      expect(final.validation_result!.checks?.length).toBeGreaterThan(0);
      await expect(page.getByRole('heading', { name: '逐动作模拟结果' })).toBeVisible();
    } else {
      assertRejected(final);
      expect(final.stop_reason).toBe(reason);
      await expect(page.getByText('尚无模拟执行结果。', { exact: true })).toBeVisible();
      await expect(page.getByText('尚无效果验证结论。审批受理不代表模拟或验证成功。', { exact: true })).toBeVisible();
      await expect(page.getByRole('heading', { name: '逐动作模拟结果' })).toHaveCount(0);
    }
    await page.reload();
    await expect(page.getByRole('heading', { name: '已记录的审批' })).toBeVisible();
    await expect(page.getByRole('complementary', { name: '人工决定' }).getByText(reason, { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '批准方案' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '拒绝方案' })).toHaveCount(0);
    await checkViewports(page, info, 'response-final-after-reload');

    if (action === 'reject') {
      const cannotApprove = await page.request.post(`/api/v1/response-plans/${context.plan.response_plan_id}/approve`, {
        headers: { Origin: context.origin, 'Idempotency-Key': `late-approve-${randomUUID()}` },
        data: { plan_version: context.plan.plan_version, reason: '拒绝后再次尝试批准' },
      });
      expect(cannotApprove.status(), await cannotApprove.text()).toBe(409);
      expect((await cannotApprove.json()).error.code).toBe('CONFLICT');
    }
    const persisted = await snapshot(request, context.investigation.investigation_id);
    expect(persisted.approval).toEqual(final.approval);
    expect(persisted.simulation).toEqual(final.simulation);
    expect(persisted.simulation_execution).toEqual(final.simulation_execution);
    expect(persisted.validation_result).toEqual(final.validation_result);
    if (action === 'reject') assertRejected(persisted);
    await page.goto(`/incidents/${context.investigation.incident_id}`);
    const progress = page.getByRole('region', { name: '六角色进度' });
    await expect(progress.locator('ol > li[data-status="completed"]')).toHaveCount(action === 'approve' ? 6 : 5);
    await checkViewports(page, info, 'incident-final');
    expect(errors, 'Both viewports and the full real browser flow must have no console or page errors').toEqual([]);
    await info.attach('persisted-live-flow.json', { body: JSON.stringify({ backend: liveEnvironment().backend.href,
      webOrigin: context.origin, alertId: context.alertId, investigationId: context.investigation.investigation_id,
      planId: context.plan.response_plan_id, viewports, consoleErrors: errors, snapshot: persisted }, null, 2),
    contentType: 'application/json' });
  });
}
