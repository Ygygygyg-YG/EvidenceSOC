import { expect, test, type Page } from '@playwright/test';
import { alertPageSchema, type AlertListItem } from '../src/features/alerts/alertsContract';
import { alertDetailSchema } from '../src/features/alerts/alertDetailContract';
import { incidentSummarySchema } from '../src/features/incidents/incidentContract';

const fixture = {
  alert_id: 'AL-e2e-only', title: '仅用于测试的告警标题', severity: 'high',
  created_at: '2026-09-29T02:00:00Z', event_ids: ['EVENT-e2e-only'], status: 'manual_review',
} satisfies AlertListItem;

async function selectOption(page: Page, name: string, option: string) {
  await page.getByRole('combobox', { name, exact: true }).click();
  await page.getByRole('option', { name: option, exact: true }).click();
}

test('真实同源 API 的 total 与默认列表一致', async ({ page, request }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const response = await request.get('/api/v1/alerts?page=1&page_size=20');
  expect(response.ok()).toBe(true);
  const actual = alertPageSchema.parse(await response.json());
  await page.goto('/alerts');
  await expect(page.getByRole('heading', { name: '告警列表', level: 1 })).toBeVisible();
  await expect(page.getByTestId('alerts-total')).toHaveText(`共 ${actual.total} 条告警`);
  if (actual.total === 0) await expect(page.getByRole('heading', { name: '暂无告警', exact: true })).toBeVisible();
  else {
    const first = actual.items[0];
    await expect(page.getByRole('table', { name: '告警记录', exact: true })).toContainText(first.title);
    const detailResponse = await request.get(`/api/v1/alerts/${encodeURIComponent(first.alert_id)}`);
    expect(detailResponse.ok()).toBe(true);
    const detail = alertDetailSchema.parse(await detailResponse.json());
    expect(detail.alert_id).toBe(first.alert_id);
    await page.goto(`/alerts/${encodeURIComponent(first.alert_id)}`);
    await expect(page.getByRole('heading', { name: first.title, level: 1 })).toBeVisible();
    if (detail.incident_id) {
      const incidentResponse = await request.get(`/api/v1/incidents/${encodeURIComponent(detail.incident_id)}`);
      expect(incidentResponse.ok()).toBe(true);
      const incident = incidentSummarySchema.parse(await incidentResponse.json());
      expect(incident.alert_id).toBe(first.alert_id);
      await page.goto(`/incidents/${encodeURIComponent(detail.incident_id)}`);
      await expect(page.getByRole('heading', { name: '案件详情' })).toBeVisible();
      await expect(page.getByText(detail.incident_id, { exact: true })).toBeVisible();
    }
  }
});

test('URL 恢复、翻页和筛选重置页码', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const receivedQueries: string[] = [];
  await page.route('**/api/v1/alerts?**', async (route) => {
    const query = new URL(route.request().url()).searchParams;
    receivedQueries.push(query.toString());
    await route.fulfill({ json: { items: [fixture], total: 140, page: Number(query.get('page')), page_size: Number(query.get('page_size')) } });
  });
  await page.goto('/alerts?page=3&page_size=50&severity=high&status=manual_review');
  await expect(page.getByTestId('alerts-total')).toHaveText('共 140 条告警');
  expect(receivedQueries.at(-1)).toBe('page=3&page_size=50&severity=high&status=manual_review');
  await selectOption(page, '严重性', '严重');
  await expect(page).toHaveURL((url) => url.searchParams.get('page') === '1' && url.searchParams.get('severity') === 'critical');
  await expect(page.getByTestId('alerts-total')).toBeVisible();
  await page.getByRole('button', { name: '下一页', exact: true }).click();
  await expect(page).toHaveURL((url) => url.searchParams.get('page') === '2');
  await page.goBack();
  await expect(page).toHaveURL((url) => url.searchParams.get('page') === '1' && url.searchParams.get('severity') === 'critical');
  await expect(page.getByTestId('alerts-total')).toHaveText('共 140 条告警');
  await page.goForward();
  await expect(page).toHaveURL((url) => url.searchParams.get('page') === '2' && url.searchParams.get('severity') === 'critical');
  await selectOption(page, '每页条数', '100 条/页');
  await expect(page).toHaveURL((url) => url.searchParams.get('page') === '1' && url.searchParams.get('page_size') === '100');
  await selectOption(page, '严重性', '全部严重性');
  await expect(page).toHaveURL((url) => !url.searchParams.has('severity') && url.searchParams.get('status') === 'manual_review');
  await selectOption(page, '当前状态', '已完成');
  await expect(page).toHaveURL((url) => url.searchParams.get('page') === '1' && url.searchParams.get('status') === 'completed');
  await page.reload();
  await expect(page.getByTestId('alerts-total')).toHaveText('共 140 条告警');
  expect(receivedQueries.at(-1)).toBe('page=1&page_size=100&status=completed');
});

test('总览时间窗口、关键词与手动日期筛选在列表和详情返回中保持一致', async ({ page }) => {
  const receivedQueries: URLSearchParams[] = [];
  const matching = { ...fixture, title: 'SQL 注入测试告警', created_at: '2026-09-29T01:00:00Z' };
  await page.route('**/api/v1/alerts?**', async (route) => {
    const query = new URL(route.request().url()).searchParams;
    receivedQueries.push(new URLSearchParams(query));
    await route.fulfill({ json: { items: [matching], total: 140,
      page: Number(query.get('page')), page_size: Number(query.get('page_size')) } });
  });
  const range = 'time_from=2026-09-29T00%3A00%3A00Z&time_to=2026-09-30T00%3A00%3A00Z';
  await page.goto(`/alerts?page=2&page_size=20&${range}`);
  await expect(page.getByTestId('alerts-total')).toHaveText('共 140 条告警');
  await expect(page.getByLabel('开始时间（UTC+8）')).toHaveValue('2026-09-29T08:00');
  await expect(page.getByLabel('结束时间（UTC+8）')).toHaveValue('2026-09-30T08:00');
  await page.getByRole('searchbox', { name: '关键词' }).fill(' SQL ');
  await expect(page).toHaveURL((url) => url.searchParams.get('query') === 'SQL' && url.searchParams.get('page') === '1');
  expect(receivedQueries.at(-1)?.get('time_from')).toBe('2026-09-29T00:00:00Z');
  await expect.poll(() => receivedQueries.at(-1)?.get('query')).toBe('SQL');
  await page.getByLabel('结束时间（UTC+8）').fill('2026-09-29T10:00');
  await page.getByRole('button', { name: '应用时间' }).click();
  await expect(page).toHaveURL((url) => url.searchParams.get('time_to') === '2026-09-29T02:00:00.000Z'
    && url.searchParams.get('query') === 'SQL');
  await page.getByRole('table', { name: '告警记录' }).getByRole('link', { name: matching.title }).click();
  await expect(page.getByRole('link', { name: '返回告警列表' })).toHaveAttribute('href',
    /time_from=2026-09-29T00%3A00%3A00Z.*time_to=2026-09-29T02%3A00%3A00.000Z.*query=SQL/);
});

test('错误显示 trace，手动重试后才进入空数据成功状态', async ({ page }) => {
  let fail = true;
  await page.route('**/api/v1/alerts?**', async (route) => {
    await route.fulfill(fail ? {
      status: 503, headers: { 'x-trace-id': 'TRACE-e2e-retry' },
      json: { error: { code: 'DEPENDENCY_UNAVAILABLE', message: '告警服务暂时不可用。', trace_id: 'TRACE-e2e-retry' } },
    } : { json: { items: [], total: 0, page: 1, page_size: 20 } });
  });
  await page.goto('/alerts');
  await expect(page.getByRole('region', { name: '告警工作区', exact: true }).getByRole('alert')).toContainText('TRACE-e2e-retry');
  await expect(page.getByTestId('alerts-total')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: '暂无告警', exact: true })).toHaveCount(0);
  fail = false;
  await page.getByRole('button', { name: '重试', exact: true }).click();
  await expect(page.getByRole('heading', { name: '暂无告警', exact: true })).toBeVisible();
  await expect(page.getByTestId('alerts-total')).toHaveText('共 0 条告警');
});

test('同一查询更新失败时保留上次结果，重试后恢复真实数据', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  let responseMode: 'success' | 'fail' | 'recovered' = 'success';
  let releaseFailure: () => void = () => {};
  const failureGate = new Promise<void>((resolve) => { releaseFailure = resolve; });
  const recovered = { ...fixture, title: '仅用于测试的更新后告警标题' };
  await page.route('**/api/v1/alerts?**', async (route) => {
    const currentMode = responseMode;
    if (currentMode === 'fail') {
      await failureGate;
      await route.fulfill({ status: 503, headers: { 'x-trace-id': 'TRACE-e2e-refresh' },
        json: { error: { code: 'DEPENDENCY_UNAVAILABLE', message: '更新服务暂时不可用。', trace_id: 'TRACE-e2e-refresh' } } });
    } else {
      await route.fulfill({ json: { items: [currentMode === 'recovered' ? recovered : fixture],
        total: currentMode === 'recovered' ? 9 : 7, page: 1, page_size: 20 } });
    }
  });
  await page.goto('/alerts');
  const workspace = page.getByRole('region', { name: '告警工作区', exact: true });
  const table = page.getByRole('table', { name: '告警记录', exact: true });
  await expect(table).toContainText(fixture.title);
  await expect(page.getByTestId('alerts-total')).toHaveText('共 7 条告警');
  responseMode = 'fail';
  try {
    await page.getByRole('button', { name: '刷新', exact: true }).click();
    await expect(workspace.getByRole('status')).toContainText('正在更新，展示上次成功结果。');
    await expect(table).toContainText(fixture.title);
    await expect(page.getByTestId('alerts-total')).toHaveText('共 7 条告警');
  } finally {
    releaseFailure();
  }
  await expect(workspace.getByRole('alert')).toContainText('更新失败，展示上次成功结果。');
  await expect(workspace.getByRole('alert')).toContainText('TRACE-e2e-refresh');
  await expect(table).toContainText(fixture.title);
  await expect(page.getByTestId('alerts-total')).toHaveText('共 7 条告警');
  await expect(page.getByRole('button', { name: '下一页', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: '暂无告警', exact: true })).toHaveCount(0);
  responseMode = 'recovered';
  await page.getByRole('button', { name: '重试', exact: true }).click();
  await expect(table).toContainText(recovered.title);
  await expect(table).not.toContainText(fixture.title);
  await expect(page.getByTestId('alerts-total')).toHaveText('共 9 条告警');
  await expect(workspace.getByRole('alert')).toHaveCount(0);
});

test('过滤无匹配与越界页分别提供真实状态', async ({ page }) => {
  await page.route('**/api/v1/alerts?**', async (route) => {
    const query = new URL(route.request().url()).searchParams;
    const filtered = query.has('severity') || query.has('status');
    const pageNumber = Number(query.get('page'));
    await route.fulfill({ json: {
      items: filtered || pageNumber > 1 ? [] : [fixture], total: filtered ? 0 : 5,
      page: pageNumber, page_size: Number(query.get('page_size')),
    } });
  });
  await page.goto('/alerts?page=2&page_size=50&severity=critical&status=manual_review');
  await expect(page.getByRole('heading', { name: '没有匹配的告警', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '清除筛选', exact: true }).click();
  await expect(page).toHaveURL((url) => url.searchParams.get('page') === '1'
    && url.searchParams.get('page_size') === '50' && !url.searchParams.has('severity') && !url.searchParams.has('status'));
  await expect(page.getByRole('table', { name: '告警记录', exact: true })).toContainText(fixture.title);
  await expect(page.getByTestId('alerts-total')).toHaveText('共 5 条告警');
  await page.goto('/alerts?page=99&page_size=20');
  await expect(page.getByRole('heading', { name: '当前页没有记录', exact: true })).toBeVisible();
  await expect(page.getByTestId('alerts-total')).toHaveText('共 5 条告警');
  await page.getByRole('button', { name: '回到第一页', exact: true }).click();
  await expect(page).toHaveURL((url) => url.searchParams.get('page') === '1');
  await expect(page.getByRole('table', { name: '告警记录', exact: true })).toContainText(fixture.title);
});

test('窄窗口使用紧凑卡片且没有页面横向溢出', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route('**/api/v1/alerts?**', (route) => route.fulfill({ json: { items: [fixture], total: 1, page: 1, page_size: 20 } }));
  await page.goto('/alerts');
  const cards = page.getByRole('list', { name: '告警卡片', exact: true });
  await expect(cards).toContainText(fixture.title);
  await expect(page.getByRole('table', { name: '告警记录', exact: true })).toBeHidden();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
});

test('告警标题可进入详情，启动调查只发一次写请求并跳转真实案件', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const record = { ...fixture, status: 'received' };
  const detail = { ...record, incident_id: null, investigation_id: null, execution_mode: 'rules', events: [
    { event_id: 'EVENT-e2e-only', source: 'application', observed_at: record.created_at,
      severity: 'high', event_type: 'http_request' },
  ] };
  await page.route('**/api/v1/alerts?**', (route) => route.fulfill({ json: { items: [record], total: 1, page: 2, page_size: 20 } }));
  await page.route('**/api/v1/alerts/AL-e2e-only', (route) => route.fulfill({ json: detail }));
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let posted = 0;
  let sessionEnabled = false;
  const session = { actor_id: 'demo-reviewer', role: 'reviewer', allowed_actions: ['approve', 'reject'], expires_at: '2030-01-01T00:00:00Z' };
  await page.route('**/api/v1/session', (route) => route.fulfill(sessionEnabled
    ? { json: session } : { status: 401, json: { error: { code: 'SESSION_REQUIRED', message: 'login required', trace_id: null } } }));
  await page.route('**/api/v1/session/demo', (route) => {
    sessionEnabled = true;
    return route.fulfill({ json: session });
  });
  await page.route('**/api/v1/investigations', async (route) => {
    posted += 1;
    expect(route.request().postDataJSON()).toEqual({ alert_id: 'AL-e2e-only', mode: 'rules' });
    expect(route.request().headers()['idempotency-key']).toMatch(/^[0-9a-f-]{36}$/);
    await gate;
    await route.fulfill({ status: 202, json: {
      investigation_id: 'INV-e2e-only', incident_id: 'IN-e2e-only', trace_id: 'TRACE-e2e',
      status: 'collecting', stream_url: '/api/v1/investigations/INV-e2e-only/stream',
    } });
  });
  await page.goto('/alerts?page=2&page_size=20');
  await page.getByRole('table', { name: '告警记录' }).getByRole('link', { name: record.title }).click();
  await expect(page).toHaveURL((url) => url.pathname === '/alerts/AL-e2e-only' && url.searchParams.get('from') === 'page=2&page_size=20');
  await expect(page.getByRole('heading', { name: record.title, level: 1 })).toBeVisible();
  await expect(page.getByText('当前运行模式：规则模式')).toBeVisible();
  await expect(page.getByText('EVENT-e2e-only')).toBeVisible();
  await expect(page.getByRole('link', { name: '返回告警列表' })).toHaveAttribute('href', '/alerts?page=2&page_size=20');
  const start = page.getByRole('button', { name: /启动调查/ });
  await expect(start).toBeDisabled();
  expect(posted).toBe(0);
  await page.getByRole('button', { name: '启用本地演示账户' }).click();
  await expect(page.getByText('demo-reviewer')).toBeVisible();
  try {
    await start.click();
    await expect(start).toBeDisabled();
    expect(posted).toBe(1);
  } finally {
    release();
  }
  await expect(page).toHaveURL((url) => url.pathname === '/incidents/IN-e2e-only');
  expect(posted).toBe(1);
});

test('已有调查显示继续入口；不存在告警显示 404 和重试，不提供启动操作', async ({ page }) => {
  const detail = { ...fixture, incident_id: 'IN-existing', investigation_id: 'INV-existing', execution_mode: 'rules', events: [
    { event_id: 'EVENT-e2e-only', source: 'application', observed_at: fixture.created_at,
      severity: 'high', event_type: 'http_request' },
  ] };
  await page.route('**/api/v1/alerts/AL-e2e-only', (route) => route.fulfill({ json: detail }));
  await page.goto('/alerts/AL-e2e-only');
  await expect(page.getByRole('link', { name: '继续调查' })).toHaveAttribute('href', '/incidents/IN-existing');
  await expect(page.getByRole('button', { name: '启动调查', exact: true })).toHaveCount(0);
  await page.route('**/api/v1/alerts/AL-missing', (route) => route.fulfill({ status: 404, json: {
    error: { code: 'NOT_FOUND', message: 'Requested resource was not found.', trace_id: 'TRACE-missing' },
  } }));
  await page.goto('/alerts/AL-missing');
  await expect(page.getByRole('heading', { name: '告警不存在' })).toBeVisible();
  await expect(page.getByText('TRACE-missing')).toBeVisible();
  await expect(page.getByRole('button', { name: '启动调查', exact: true })).toHaveCount(0);
});

test('已有案件但尚无调查时仍可启动调查', async ({ page }) => {
  const detail = { ...fixture, incident_id: 'IN-existing', investigation_id: null, execution_mode: 'rules', events: [
    { event_id: 'EVENT-e2e-only', source: 'application', observed_at: fixture.created_at,
      severity: 'high', event_type: 'http_request' },
  ] };
  await page.route('**/api/v1/alerts/AL-e2e-only', (route) => route.fulfill({ json: detail }));
  await page.goto('/alerts/AL-e2e-only');
  await expect(page.getByRole('button', { name: '启动调查', exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: '继续调查' })).toHaveCount(0);
});
