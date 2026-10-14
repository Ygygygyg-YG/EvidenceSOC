import { expect, test } from '@playwright/test';
import type { components } from '../src/lib/api/generated';

type IncidentDetail = components['schemas']['IncidentDetail'];

const incident: IncidentDetail = {
  incident_id: 'IN-E2E123', alert_id: 'AL-E2E123', status: 'collecting',
  created_at: '2026-09-21T10:20:24Z', investigation_id: 'IV-E2E123', trace_id: 'TRACE-E2E123',
  alerts: [{ alert_id: 'AL-E2E123', title: 'SQL 注入测试告警', severity: 'high',
    created_at: '2026-09-21T10:20:24Z', event_ids: ['EVT-E2E123'] }],
  evidence: [{ evidence_id: 'EV-01K5TESTTESTTESTTESTTESTTEST', event_id: 'EVT-E2E123',
    source: 'nginx', observed_at: '2026-09-21T10:20:24Z', query: { term: 'test' },
    summary: '请求包含异常 SQL 参数', content_sha256: 'a'.repeat(64) }],
  knowledge: [],
  attack_steps: [{ attack_step_id: 'STEP-E2E123', sequence: 1, phase: 'initial_access',
    technique_id: 'T1190', description: '外部应用遭到尝试访问', occurred_at: '2026-09-21T10:20:24Z',
    evidence_ids: ['EV-01K5TESTTESTTESTTESTTESTTEST'], incident_id: 'IN-E2E123' }],
  runs: [{ run_id: 'RUN-E2E123', incident_id: 'IN-E2E123', agent_name: 'triage',
    status: 'completed', started_at: '2026-09-21T10:20:24Z', finished_at: '2026-09-21T10:21:24Z',
    evidence_ids: ['EV-01K5TESTTESTTESTTESTTESTTEST'] }],
  origin: null, classification: null, response_plan: null, approval: null,
  validation_result: null, simulation: [], fallback_used: false, errors: [], stop_reason: null,
};

test('可直接打开案件 URL，展示真实案件、告警、证据、步骤和运行摘要', async ({ page }) => {
  let requestedPath = '';
  await page.route('**/api/v1/incidents/IN-E2E123', async (route) => {
    requestedPath = new URL(route.request().url()).pathname;
    await route.fulfill({ json: incident });
  });
  await page.goto('/incidents/IN-E2E123');
  await expect(page.getByRole('heading', { name: '案件详情', level: 1 })).toBeVisible();
  await expect(page.getByText('IN-E2E123', { exact: true })).toBeVisible();
  await expect(page.getByText('IV-E2E123', { exact: true })).toBeVisible();
  await expect(page.getByText('SQL 注入测试告警')).toBeVisible();
  await expect(page.getByText('请求包含异常 SQL 参数')).toBeVisible();
  await expect(page.getByText('外部应用遭到尝试访问')).toBeVisible();
  await expect(page.getByText('triage')).toBeVisible();
  expect(requestedPath).toBe('/api/v1/incidents/IN-E2E123');
  await page.reload();
  await expect(page.getByText('SQL 注入测试告警')).toBeVisible();
});

test('加载中明确提示，完成后才显示后端记录', async ({ page }) => {
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/api/v1/incidents/IN-E2E123', async (route) => {
    await gate;
    await route.fulfill({ json: incident });
  });
  try {
    await page.goto('/incidents/IN-E2E123');
    await expect(page.getByRole('status')).toContainText('正在加载案件');
    await expect(page.getByText('SQL 注入测试告警')).toHaveCount(0);
  } finally {
    release();
  }
  await expect(page.getByText('SQL 注入测试告警')).toBeVisible();
});

test('404 显示案件不存在，与服务故障区分', async ({ page }) => {
  await page.route('**/api/v1/incidents/IN-MISSING', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'NOT_FOUND', message: 'incident does not exist', trace_id: 'TRACE-missing' } },
  }));
  await page.goto('/incidents/IN-MISSING');
  await expect(page.getByRole('heading', { name: '案件不存在' })).toBeVisible();
  await expect(page.getByRole('link', { name: '返回告警列表' })).toHaveAttribute('href', '/alerts');
  await expect(page.getByText('SQL 注入测试告警')).toHaveCount(0);
});

test('服务错误展示 trace，点击重试后显示实际记录', async ({ page }) => {
  let fail = true;
  await page.route('**/api/v1/incidents/IN-E2E123', (route) => route.fulfill(fail ? {
    status: 503, headers: { 'x-trace-id': 'TRACE-unavailable' },
    json: { error: { code: 'DEPENDENCY_UNAVAILABLE', message: '案件服务暂时不可用。', trace_id: 'TRACE-unavailable' } },
  } : { json: incident }));
  await page.goto('/incidents/IN-E2E123');
  await expect(page.getByRole('region', { name: '案件工作区' }).getByRole('alert')).toContainText('TRACE-unavailable');
  await expect(page.getByText('SQL 注入测试告警')).toHaveCount(0);
  fail = false;
  await page.getByRole('button', { name: '重试' }).click();
  await expect(page.getByText('SQL 注入测试告警')).toBeVisible();
});
