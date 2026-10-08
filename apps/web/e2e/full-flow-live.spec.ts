import { randomUUID } from 'node:crypto';
import { expect, test } from '@playwright/test';

const seedAlertId = process.env.TASK10_LIVE_SEED_ALERT_ID;
const isolatedBackend = process.env.TASK10_LIVE_ISOLATED_BACKEND;

test('真实规则调查经页面完成证据核验、人工批准与模拟验证', async ({ page, request }) => {
  test.setTimeout(120_000);
  test.skip(!seedAlertId || !isolatedBackend, '需要隔离后端及已导入的样例告警');
  const backend = new URL(isolatedBackend!);
  expect(['127.0.0.1', 'localhost']).toContain(backend.hostname);

  const seedResponse = await request.get(new URL(`/api/v1/alerts/${seedAlertId}`, backend).toString());
  expect(seedResponse.ok()).toBe(true);
  const seed = await seedResponse.json() as { event_ids: string[]; created_at: string };
  expect(seed.event_ids.length).toBeGreaterThan(0);
  const suffix = randomUUID();
  const alertId = `AL-TASK10-LIVE-${suffix}`;
  const title = `Task10 真实闭环 ${suffix}`;
  const created = await request.post(new URL('/api/v1/alerts', backend).toString(), {
    headers: { 'Idempotency-Key': `task10-live-${suffix}` },
    data: { alert_id: alertId, title, severity: 'high', created_at: seed.created_at, event_ids: seed.event_ids },
  });
  expect(created.status(), await created.text()).toBe(201);

  await page.goto(`/alerts?query=${encodeURIComponent(title)}`);
  await page.getByRole('table', { name: '告警记录' }).getByRole('link', { name: title }).click();
  await expect(page.getByRole('heading', { name: title, level: 1 })).toBeVisible();
  await page.getByRole('button', { name: '启用本地演示账户' }).click();
  await expect(page.getByText('demo-reviewer')).toBeVisible();
  await page.getByRole('button', { name: '启动调查', exact: true }).click();
  await expect(page).toHaveURL(/\/incidents\/IN-/);
  await expect(page.getByRole('region', { name: '六角色进度' })).toBeVisible();
  await expect(page.getByRole('link', { name: /查看响应方案/ })).toBeVisible({ timeout: 60_000 });

  await page.getByRole('button', { name: '阶段列表' }).click();
  await page.getByRole('button', { name: /^第 1 步 / }).click();
  const inspector = page.getByRole('region', { name: '证据检查器' }).first();
  await expect(inspector).toContainText('第 1 步引用的证据');
  await inspector.locator('ul button').first().click();
  await expect(inspector.getByText('PostgreSQL 本次校验通过')).toBeVisible();
  const drawer = page.getByRole('dialog', { name: '证据检查器' });
  if (await drawer.isVisible()) {
    await drawer.getByRole('button', { name: '关闭' }).click();
    await expect(drawer).toBeHidden();
  }

  await page.getByRole('link', { name: /查看响应方案/ }).click();
  await expect(page.getByRole('heading', { name: '人工决定' })).toBeVisible();
  await expect(page.getByText('demo-reviewer')).toBeVisible();
  await page.getByRole('textbox', { name: '决定理由' }).fill('已核对原始证据、模拟影响与回滚计划');
  await page.getByRole('button', { name: '批准方案' }).click();
  await page.getByRole('button', { name: '确认提交批准' }).click();
  await expect(page.getByRole('heading', { name: '验证成功' })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByRole('heading', { name: '已记录的审批' })).toBeVisible();
});
