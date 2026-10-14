import { expect, test } from '@playwright/test';

const record = {
  incident_id: 'IN-list-test', investigation_id: 'IV-list-test', alert_id: 'AL-list-test',
  alert_title: 'SQL 注入演示告警', severity: 'high', status: 'awaiting_approval',
  created_at: '2026-09-30T02:00:00Z', evidence_count: 10, validation_outcome: null,
};

test('调查列表展示真实分页和详情入口，URL 恢复状态筛选', async ({ page }) => {
  const queries: string[] = [];
  await page.route('**/api/v1/incidents?**', (route) => {
    const query = new URL(route.request().url()).searchParams;
    queries.push(query.toString());
    return route.fulfill({ json: { items: [record], total: 30, page: Number(query.get('page')), page_size: Number(query.get('page_size')) } });
  });
  await page.goto('/incidents?page=2&page_size=20&status=awaiting_approval');
  await expect(page.getByRole('heading', { name: '调查列表', level: 1 })).toBeVisible();
  await expect(page.getByTestId('incidents-total')).toHaveText('共 30 条案件');
  await expect(page.getByRole('link', { name: record.incident_id })).toHaveAttribute('href',
    '/incidents/IN-list-test?from=page%3D2%26page_size%3D20%26status%3Dawaiting_approval');
  expect(queries.at(-1)).toBe('page=2&page_size=20&status=awaiting_approval');
});

test('调查列表区分失败和空数据，手动重试', async ({ page }) => {
  let fail = true;
  await page.route('**/api/v1/incidents?**', (route) => route.fulfill(fail ? {
    status: 503, json: { error: { code: 'DEPENDENCY_UNAVAILABLE', message: '案件服务不可用', trace_id: 'TRACE-incident-list' } },
  } : { json: { items: [], total: 0, page: 1, page_size: 20 } }));
  await page.goto('/incidents');
  await expect(page.getByRole('region', { name: '案件工作区' }).getByRole('alert')).toContainText('TRACE-incident-list');
  await expect(page.getByText('共 0 条案件')).toHaveCount(0);
  fail = false;
  await page.getByRole('button', { name: '重试' }).click();
  await expect(page.getByRole('heading', { name: '暂无案件' })).toBeVisible();
  await expect(page.getByTestId('incidents-total')).toHaveText('共 0 条案件');
});

test('调查列表刷新和详情返回保留时间窗口与高危筛选', async ({ page }) => {
  const queries: string[] = [];
  await page.route('**/api/v1/incidents?**', (route) => {
    const query = new URL(route.request().url()).searchParams;
    queries.push(query.toString());
    return route.fulfill({ json: { items: [record], total: 1, page: Number(query.get('page')), page_size: Number(query.get('page_size')) } });
  });
  const query = 'page=1&page_size=20&risk=high&time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z';
  await page.setViewportSize({ width: 390, height: 840 });
  await page.goto(`/incidents?${query}`);
  await expect(page.getByTestId('incidents-total')).toHaveText('共 1 条案件');
  await expect(page.getByText('时间区间按案件创建时间筛选')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(queries.at(-1)).toBe(query);
  await page.reload();
  await expect(page.getByTestId('incidents-total')).toHaveText('共 1 条案件');
  expect(queries.at(-1)).toBe(query);
  await page.getByRole('link', { name: record.incident_id }).first().click();
  await expect(page.getByRole('link', { name: '返回调查列表' })).toHaveAttribute('href', `/incidents?${query}`);
  await page.getByRole('link', { name: '返回调查列表' }).click();
  await expect(page).toHaveURL((url) => url.pathname === '/incidents' && url.searchParams.get('risk') === 'high'
    && url.searchParams.get('time_from') === '2026-09-30T00:00:00Z');
});
