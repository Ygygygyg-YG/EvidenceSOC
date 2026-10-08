import { expect, test } from '@playwright/test';
import { responseDetailSchema, responsePageSchema } from '../src/features/responses/responseContract';

const action = {
  action: 'block_ip_simulated', target: '198.51.100.42', risk: '低风险',
  impact: '只影响样例流量', preview: '在回放环境模拟限制异常来源',
  rollback: '撤销模拟限制', verification_query: { filters: { source_ip: '198.51.100.42' } },
};
const planVersion = 'a'.repeat(64);
const item = {
  response_plan_id: 'RP-test', incident_id: 'IN-test', investigation_id: 'IV-test',
  alert_id: 'AL-test', alert_title: '可疑来源访问', severity: 'high', incident_status: 'awaiting_approval',
  summary: '限制异常来源并验证正常请求', actions: [action], created_at: '2026-09-29T02:00:00Z',
  requires_approval: true, evidence_ids: ['EV-test'], decision_state: 'pending', is_current: true,
  execution_mode: 'simulation', risk_level: 'low', risk_reason: '仅影响样例流量',
  affected_assets: ['198.51.100.42'], business_impact: '不影响生产链路',
  expires_at: '2026-10-30T02:00:00Z', is_expired: false,
  rollback_steps: [{ step_id: 'RB-test', description: '撤销模拟限制', target: '198.51.100.42',
    expected_result: '样例环境恢复', evidence_ids: ['EV-test'] }],
  validation_checks: [{ check_id: 'VC-test', description: '复查访问', target: '198.51.100.42',
    expected_result: '异常请求停止', query: { filters: { source_ip: '198.51.100.42' } }, evidence_ids: ['EV-test'] }],
  plan_version: planVersion,
} as const;
const pendingDetail = responseDetailSchema.parse({
  ...item, plan_version: planVersion, approval: null, validation_result: null, simulation: [], pending_decision: null,
  available_actions: ['approve', 'reject'],
});
const session = {
  actor_id: 'demo-reviewer', role: 'reviewer', allowed_actions: ['approve', 'reject'],
  expires_at: '2026-10-01T06:30:00Z',
};

test.beforeEach(async ({ page }) => {
  await page.route('**/api/v1/session', async (route) => route.fulfill({ json: session }));
});

test('响应队列使用服务端 total 和状态筛选，链接进入真实方案详情', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const queries: string[] = [];
  await page.route('**/api/v1/response-plans?**', async (route) => {
    const query = new URL(route.request().url()).searchParams;
    queries.push(query.toString());
    await route.fulfill({ json: responsePageSchema.parse({
      items: [item], total: 21, page: Number(query.get('page')), page_size: Number(query.get('page_size')),
    }) });
  });
  await page.route('**/api/v1/response-plans/RP-test', async (route) => route.fulfill({ json: pendingDetail }));
  await page.goto('/responses?page=2&page_size=20&decision_state=pending');
  await expect(page.getByRole('heading', { name: '响应审批', level: 1 })).toBeVisible();
  await expect(page.getByTestId('responses-total')).toHaveText('共 21 个方案');
  expect(queries.at(-1)).toBe('page=2&page_size=20&decision_state=pending');
  await page.getByRole('link', { name: 'RP-test' }).first().click();
  await expect(page).toHaveURL(/\/responses\/RP-test/);
  await expect(page.getByRole('heading', { name: item.summary, level: 1 })).toBeVisible();
  await expect(page.getByText('仅模拟处置', { exact: false }).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: '回滚计划' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '验证条件' })).toBeVisible();
  await expect(page.getByText('不影响生产链路')).toBeVisible();
});

test('已过期方案显示有效期并阻止审批提交', async ({ page }) => {
  let requests = 0;
  let renewals = 0;
  await page.route('**/api/v1/response-plans/RP-test', (route) => route.fulfill({ json: responseDetailSchema.parse({
    ...pendingDetail, is_expired: true, expires_at: '2026-09-29T02:30:00Z', available_actions: [],
  }) }));
  await page.route('**/api/v1/response-plans/RP-test/approve', (route) => {
    requests += 1;
    return route.fulfill({ status: 410, json: { error: { code: 'PLAN_EXPIRED', message: 'expired', trace_id: null } } });
  });
  await page.route('**/api/v1/response-plans/RP-test/renew', (route) => {
    renewals += 1;
    expect(route.request().postDataJSON()).toEqual({ plan_version: planVersion });
    expect(route.request().headers()['idempotency-key']).toMatch(/^[0-9a-f-]{36}$/);
    return route.fulfill({ status: 202, json: {
      response_plan_id: 'RP-test', investigation_id: 'IV-test', incident_id: 'IN-test',
      trace_id: 'TRACE-renew', status: 'accepted', stream_url: '/api/v1/investigations/IV-test/stream',
    } });
  });
  await page.goto('/responses/RP-test');
  await expect(page.getByRole('alert').filter({ hasText: '方案已过期' })).toBeVisible();
  await expect(page.getByRole('button', { name: '批准方案' })).toHaveCount(0);
  await page.getByRole('button', { name: '重新生成方案' }).click();
  await expect(page.getByRole('link', { name: '查看续办调查' })).toHaveAttribute('href', '/incidents/IN-test');
  expect(renewals).toBe(1);
  expect(requests).toBe(0);
});

test('旧方案缺少审查字段时说明原因且只允许拒绝', async ({ page }) => {
  await page.route('**/api/v1/response-plans/RP-test', (route) => route.fulfill({ json: responseDetailSchema.parse({
    ...pendingDetail, risk_level: null, risk_reason: null, affected_assets: [],
    business_impact: null, expires_at: null, rollback_steps: [], validation_checks: [],
    available_actions: ['reject'],
  }) }));
  await page.goto('/responses/RP-test');
  await expect(page.getByRole('alert').filter({ hasText: '此方案缺少' })).toContainText('风险说明、业务影响、有效期、回滚计划、验证条件');
  await expect(page.getByRole('button', { name: '批准方案' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '拒绝方案' })).toBeVisible();
});

test('旧方案仅缺动作追溯字段时说明不能批准的原因', async ({ page }) => {
  await page.route('**/api/v1/response-plans/RP-test', (route) => route.fulfill({ json: responseDetailSchema.parse({
    ...pendingDetail, available_actions: ['reject'],
  }) }));
  await page.goto('/responses/RP-test');
  await expect(page.getByRole('alert').filter({ hasText: '此方案缺少' })).toContainText('动作追溯信息');
  await expect(page.getByRole('button', { name: '批准方案' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '拒绝方案' })).toBeVisible();
});

test('新方案能按动作编号追踪模拟结果、回滚与验证时间窗', async ({ page }) => {
  const traced = responseDetailSchema.parse({
    ...pendingDetail, decision_state: 'approved', incident_status: 'completed', available_actions: [],
    actions: [{ ...action, action_id: 'ACT-test', type: action.action,
      parameters: { source_ip: action.target }, expected_effect: '异常请求停止',
      rollback_ref: 'RB-test', evidence_ids: ['EV-test'] }],
    simulation_execution: {
      simulation_id: 'SIM-test', response_plan_id: 'RP-test', plan_version: planVersion,
      status: 'completed', started_at: '2026-09-29T03:00:00Z', finished_at: '2026-09-29T03:00:05Z',
      action_results: [{ action_id: 'ACT-test', outcome: 'success', description: '样例流量已模拟限制',
        started_at: '2026-09-29T03:00:00Z', finished_at: '2026-09-29T03:00:05Z' }], error: null,
    },
    validation_result: {
      validation_id: 'VR-test', response_plan_id: 'RP-test', outcome: 'success',
      summary: '异常请求停止', checked_at: '2026-09-29T03:02:00Z', evidence_ids: ['EV-test'],
      time_from: '2026-09-29T03:00:00Z', time_to: '2026-09-29T03:02:00Z',
      checks: [{ check_id: 'VC-test', condition: { filters: { source_ip: action.target } },
        outcome: 'success', evidence_ids: ['EV-test'], explanation: '查询结果符合预期' }],
    },
  });
  await page.route('**/api/v1/response-plans/RP-test', (route) => route.fulfill({ json: traced }));
  await page.goto('/responses/RP-test');
  await expect(page.getByRole('heading', { name: '拟模拟的动作' })).toBeVisible();
  await expect(page.getByText('ACT-test').first()).toBeVisible();
  await expect(page.getByText('异常请求停止').first()).toBeVisible();
  await expect(page.getByText('关联回滚步骤：RB-test')).toBeVisible();
  await expect(page.getByRole('heading', { name: '逐动作模拟结果' })).toBeVisible();
  await expect(page.getByText('样例流量已模拟限制')).toBeVisible();
  await expect(page.getByText('验证时间窗（UTC+8）')).toBeVisible();
  await expect(page.getByText('VC-test').last()).toBeVisible();
  await expect(page.getByText('查询结果符合预期')).toBeVisible();
  await expect(page.getByRole('link', { name: 'EV-test' }).first()).toHaveAttribute('href', '/incidents/IN-test');
});

test('理由必填且审批人来自会话；202 后只展示服务端提交中状态', async ({ page }) => {
  let detail = pendingDetail;
  const posted: Array<{ plan_version: string; reason: string }> = [];
  const idempotencyKeys: string[] = [];
  await page.route('**/api/v1/response-plans/RP-test', async (route) => route.fulfill({ json: detail }));
  await page.route('**/api/v1/response-plans/RP-test/approve', async (route) => {
    posted.push(route.request().postDataJSON());
    idempotencyKeys.push(route.request().headers()['idempotency-key']);
    detail = responseDetailSchema.parse({
      ...pendingDetail, decision_state: 'submitting', pending_decision: 'approved', available_actions: [],
    });
    await route.fulfill({ status: 202, json: {
      response_plan_id: 'RP-test', investigation_id: 'IV-test', incident_id: 'IN-test',
      trace_id: 'TRACE-accepted', decision: 'approved', status: 'accepted',
    } });
  });
  await page.goto('/responses/RP-test');
  await page.getByRole('button', { name: '批准方案' }).click();
  await expect(page.getByRole('alert').filter({ hasText: '请填写决定理由' })).toBeVisible();
  expect(posted).toHaveLength(0);
  await expect(page.getByText('demo-reviewer')).toBeVisible();
  await expect(page.getByRole('textbox', { name: '审批人标识' })).toHaveCount(0);
  await page.getByRole('textbox', { name: '决定理由' }).fill(' 已核对证据与模拟影响 ');
  await page.getByRole('button', { name: '批准方案' }).click();
  await expect(page.getByRole('dialog', { name: '确认批准' })).toContainText('已核对证据与模拟影响');
  await page.getByRole('button', { name: '确认提交批准' }).click();
  await expect(page.getByText('审批请求已受理', { exact: false })).toBeVisible();
  await expect(page.getByText('提交中', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: '批准方案' })).toHaveCount(0);
  expect(posted).toEqual([{ plan_version: planVersion, reason: '已核对证据与模拟影响' }]);
  expect(idempotencyKeys).toHaveLength(1);
  expect(idempotencyKeys[0]).toMatch(/^[0-9a-f-]{36}$/);
});

test('409 后重读服务端结果，不自动重新提交决定', async ({ page }) => {
  let detail = pendingDetail;
  let requests = 0;
  await page.route('**/api/v1/response-plans/RP-test', async (route) => route.fulfill({ json: detail }));
  await page.route('**/api/v1/response-plans/RP-test/reject', async (route) => {
    requests += 1;
    detail = responseDetailSchema.parse({
      ...pendingDetail, decision_state: 'approved', incident_status: 'simulating',
      pending_decision: null, available_actions: [],
      approval: {
        approval_id: 'AP-test', response_plan_id: 'RP-test', decision: 'approved',
        reason: '另一个审批人已批准', decided_by: 'other', decided_at: '2026-09-29T03:00:00Z',
      },
    });
    await route.fulfill({ status: 409, json: {
      error: { code: 'ALREADY_DECIDED', message: '方案已决定。', trace_id: 'TRACE-conflict' },
    } });
  });
  await page.goto('/responses/RP-test');
  await page.getByRole('textbox', { name: '决定理由' }).fill('证据不足');
  await page.getByRole('button', { name: '拒绝方案' }).click();
  await page.getByRole('button', { name: '确认提交拒绝' }).click();
  await expect(page.getByRole('alert').filter({ hasText: '方案已决定' })).toBeVisible();
  await expect(page.getByText('已批准', { exact: true }).first()).toBeVisible();
  expect(requests).toBe(1);
});

test('批准后服务端先提交中再完成模拟验证，页面自动追踪到结论', async ({ page }) => {
  let accepted = false;
  let polls = 0;
  let requests = 0;
  const submitting = responseDetailSchema.parse({
    ...pendingDetail, decision_state: 'submitting', pending_decision: 'approved', available_actions: [],
  });
  const completed = responseDetailSchema.parse({
      ...pendingDetail, decision_state: 'approved', incident_status: 'completed',
      pending_decision: null, available_actions: [],
      approval: {
        approval_id: 'AP-test', response_plan_id: 'RP-test', decision: 'approved',
        reason: '证据与影响已核对', decided_by: 'reviewer-1', decided_at: '2026-09-29T03:00:00Z',
      },
      simulation: [{ ...action, execution_id: 'RP-test:0', simulated: true,
        status: 'completed', outcome: 'simulated_block' }],
      validation_result: {
        validation_id: 'VR-test', response_plan_id: 'RP-test', outcome: 'success',
        summary: '模拟限制后异常请求停止，正常请求保留。', checked_at: '2026-09-29T03:01:00Z',
        evidence_ids: ['EV-test'],
      },
  });
  await page.route('**/api/v1/response-plans/RP-test', (route) => {
    if (!accepted) return route.fulfill({ json: pendingDetail });
    polls += 1;
    return route.fulfill({ json: polls < 3 ? submitting : completed });
  });
  await page.route('**/api/v1/response-plans/RP-test/approve', async (route) => {
    requests += 1;
    accepted = true;
    await route.fulfill({ status: 202, json: {
      response_plan_id: 'RP-test', investigation_id: 'IV-test', incident_id: 'IN-test',
      trace_id: 'TRACE-accepted', decision: 'approved', status: 'accepted',
    } });
  });
  await page.goto('/responses/RP-test');
  await expect(page.getByText('尚无效果验证结论', { exact: false })).toBeVisible();
  await page.getByRole('textbox', { name: '决定理由' }).fill('证据与影响已核对');
  await page.getByRole('button', { name: '批准方案' }).click();
  await page.getByRole('button', { name: '确认提交批准' }).click();
  await expect(page.getByText('提交中', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: '验证成功' })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText('模拟限制后异常请求停止，正常请求保留。')).toBeVisible();
  await expect(page.getByText('执行编号：RP-test:0')).toBeVisible();
  await expect(page.getByText('已记录的审批')).toBeVisible();
  expect(requests).toBe(1);
  expect(polls).toBeGreaterThanOrEqual(3);
});

test('没有有效会话时禁止审批，启用本地演示账户后才可提交', async ({ page }) => {
  let authenticated = false;
  await page.route('**/api/v1/session', async (route) => {
    if (authenticated) return route.fulfill({ json: session });
    return route.fulfill({ status: 401, json: {
      error: { code: 'SESSION_REQUIRED', message: '未登录', trace_id: 'TRACE-auth' },
    } });
  });
  await page.route('**/api/v1/session/demo', async (route) => {
    authenticated = true;
    await route.fulfill({ json: session });
  });
  await page.route('**/api/v1/response-plans/RP-test', async (route) => route.fulfill({ json: pendingDetail }));
  await page.goto('/responses/RP-test');
  await expect(page.getByRole('button', { name: '批准方案' })).toBeDisabled();
  await expect(page.getByRole('button', { name: '拒绝方案' })).toBeDisabled();
  await page.getByRole('button', { name: '启用本地演示账户' }).click();
  await expect(page.getByText('demo-reviewer')).toBeVisible();
  await expect(page.getByRole('button', { name: '批准方案' })).toBeEnabled();
});
