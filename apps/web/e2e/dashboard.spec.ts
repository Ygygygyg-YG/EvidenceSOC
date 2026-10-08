import { expect, test } from '@playwright/test';
import { dashboardSchema } from '../src/features/dashboard/dashboardContract';

const sample = dashboardSchema.parse({
  window: '7d', execution_mode: 'rules', time_from: '2026-09-24T00:00:00Z', time_to: '2026-10-01T00:00:00Z',
  generated_at: '2026-10-01T00:00:00Z',
  metrics: { alerts_in_window: 2, high_risk_incidents: 1, running_investigations: 0, pending_response_plans: 1 },
  alert_trend: [
    { bucket_start: '2026-09-24T00:00:00Z', bucket_end: '2026-09-25T00:00:00Z', total: 1, high_risk: 1 },
    { bucket_start: '2026-09-25T00:00:00Z', bucket_end: '2026-09-26T00:00:00Z', total: 1, high_risk: 0 },
  ],
  incident_status_distribution: [{ status: 'awaiting_approval', count: 1 }],
  recent_alerts: [{ alert_id: 'AL-DASH', title: '真实聚合的可疑请求', severity: 'high',
    created_at: '2026-09-24T02:00:00Z', event_ids: ['SE-DASH'], status: 'awaiting_approval' }],
  recent_activity: [{ event: 'approval.required', occurred_at: '2026-09-24T03:00:00Z',
    incident_id: 'IN-DASH', investigation_id: 'IV-DASH' }],
  source_health: { checked_at: '2026-10-01T00:00:00Z', postgresql_status: 'ok', opensearch_status: null,
    is_stale: false, sources: [{ source: 'nginx', last_ingested_at: '2026-09-24T01:00:00Z',
      ingestion_lag_seconds: 600, status: null, is_stale: null }] },
});

test('首页展示真实后端聚合值，与同源 API 一致', async ({ page, request }) => {
  const response = await request.get('/api/v1/dashboard/summary?window=24h');
  expect(response.ok()).toBe(true);
  const actual = dashboardSchema.parse(await response.json());
  await page.goto('/?window=24h');
  const metrics = page.getByTestId('overview-metrics');
  await expect(metrics.getByText('窗口内告警').locator('..').locator('dd').first()).toHaveText(String(actual.metrics.alerts_in_window));
  await expect(metrics.getByText('当前待审批方案').locator('..').locator('dd').first()).toHaveText(String(actual.metrics.pending_response_plans));
});

test('窗口图表、状态下钻和未知健康按后端数据展示，窄屏不溢出', async ({ page }) => {
  await page.route('**/api/v1/dashboard/summary?**', async (route) => route.fulfill({ json: sample }));
  await page.route('**/api/v1/data-sources/health', async (route) => route.fulfill({ json: sample.source_health }));
  await page.setViewportSize({ width: 390, height: 840 });
  await page.goto('/?window=7d');
  await expect(page.getByRole('heading', { name: '运营总览', level: 1 })).toBeVisible();
  await expect(page.getByRole('img', { name: /窗口内告警趋势/ })).toBeVisible();
  await expect(page.getByRole('link', { name: '查看告警列表' })).toHaveAttribute('href',
    '/alerts?page=1&page_size=20&time_from=2026-09-24T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
  await expect(page.getByRole('link', { name: '查看全部' })).toHaveAttribute('href',
    '/alerts?page=1&page_size=20&time_from=2026-09-24T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
  await expect(page.getByRole('link', { name: '查看窗口告警列表' })).toHaveAttribute('href',
    '/alerts?page=1&page_size=20&time_from=2026-09-24T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
  await page.getByText('查看每个时间段的准确数量').click();
  await expect(page.getByRole('link', { name: '查看 2026-09-24T00:00:00Z 时间段的 1 条告警' })).toHaveAttribute('href',
    '/alerts?page=1&page_size=20&time_from=2026-09-24T00%3A00%3A00Z&time_to=2026-09-25T00%3A00%3A00Z');
  await expect(page.getByRole('link', { name: '真实聚合的可疑请求' })).toHaveAttribute('href',
    '/alerts/AL-DASH?from=page%3D1%26page_size%3D20%26time_from%3D2026-09-24T00%253A00%253A00Z%26time_to%3D2026-10-01T00%253A00%253A00Z');
  await expect(page.getByRole('link', { name: '待审批' })).toHaveAttribute('href',
    '/incidents?page=1&page_size=20&status=awaiting_approval&time_from=2026-09-24T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
  await expect(page.getByRole('link', { name: '查看调查列表' }).first()).toHaveAttribute('href',
    '/incidents?page=1&page_size=20&risk=high&time_from=2026-09-24T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
  await expect(page.getByRole('link', { name: '查看调查列表' }).nth(1)).toHaveAttribute('href', '/incidents');
  await expect(page.getByRole('heading', { name: '数据源健康' }).locator('..').locator('..')).toContainText('实时可核实项');
  await expect(page.getByText('OpenSearch').locator('..')).toContainText('未知');
  await expect(page.getByText('距最后入库：600 秒')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('点击窗口内高危调查，列表请求沿用服务端时间边界和高危口径', async ({ page }) => {
  await page.route('**/api/v1/dashboard/summary?**', (route) => route.fulfill({ json: sample }));
  await page.route('**/api/v1/data-sources/health', (route) => route.fulfill({ json: sample.source_health }));
  const queries: string[] = [];
  await page.route('**/api/v1/incidents?**', (route) => {
    const query = new URL(route.request().url()).searchParams;
    queries.push(query.toString());
    return route.fulfill({ json: { items: [], total: 0, page: Number(query.get('page')), page_size: Number(query.get('page_size')) } });
  });
  await page.goto('/?window=7d');
  await page.getByText('窗口内高危调查').locator('..').getByRole('link', { name: '查看调查列表' }).click();
  await expect(page.getByRole('heading', { name: '调查列表', level: 1 })).toBeVisible();
  await expect(page.getByTestId('incidents-total')).toHaveText('共 0 条案件');
  expect(queries.at(-1)).toBe('page=1&page_size=20&risk=high&time_from=2026-09-24T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
});

test('统计服务错误显示 trace，不把未知数据伪装为 0', async ({ page }) => {
  await page.route('**/api/v1/dashboard/summary?**', (route) => route.fulfill({
    status: 503, json: { error: { code: 'DASHBOARD_UNAVAILABLE', message: '统计服务不可用', trace_id: 'TRACE-dashboard-down' } },
  }));
  await page.goto('/');
  await expect(page.getByRole('alert').filter({ hasText: 'TRACE-dashboard-down' })).toBeVisible();
  await expect(page.getByTestId('overview-metrics')).toHaveCount(0);
});
