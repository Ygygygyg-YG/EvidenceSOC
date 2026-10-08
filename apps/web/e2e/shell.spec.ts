import { expect, test, type Page } from '@playwright/test';

async function expectNoHorizontalOverflow(page: Page) {
  const sizes = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(sizes.document).toBeLessThanOrEqual(sizes.viewport);
  expect(sizes.body).toBeLessThanOrEqual(sizes.viewport);
}

for (const viewport of [
  { width: 1440, height: 900 },
  { width: 1920, height: 1080 },
  { width: 1280, height: 800 },
  { width: 1024, height: 768 },
  { width: 390, height: 844 },
]) {
  test(`运营总览在 ${viewport.width}px 下没有横向溢出`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await page.goto('/');
    await expect(page.getByRole('heading', { name: '运营总览', level: 1 })).toBeVisible();
    await expect(page.getByRole('banner').getByRole('link', { name: 'EvidenceSOC 首页' })).toBeVisible();
    await expect(page.getByTestId('overview-metrics').getByText('窗口内告警')).toBeVisible();
    await expect(page.getByRole('heading', { name: '数据源健康', level: 2 })).toBeVisible();
    await expectNoHorizontalOverflow(page);
  });
}

test('桌面导航可进入四个工作区并保留外壳', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  const navigation = page.getByRole('navigation', { name: '主导航', exact: true });
  const shell = page.getByTestId('soc-shell');
  await expect(navigation).toBeVisible();
  await expect(page.getByRole('button', { name: '打开导航菜单', exact: true })).toBeHidden();
  await shell.evaluate((element) => element.setAttribute('data-e2e-marker', 'persisted'));

  for (const destination of [
    { href: '/alerts', title: '告警列表' },
    { href: '/incidents', title: '调查列表' },
    { href: '/responses', title: '响应审批' },
    { href: '/', title: '运营总览' },
  ]) {
    const link = navigation.getByRole('link', { name: destination.title, exact: true });
    await link.click();
    await expect(page.getByRole('heading', { name: destination.title, level: 1 })).toBeVisible();
    await expect(page).toHaveURL((url) => url.pathname === destination.href);
    await expect(link).toHaveAttribute('aria-current', 'page');
    await expect(shell).toHaveAttribute('data-e2e-marker', 'persisted');
    await expectNoHorizontalOverflow(page);
  }
});

test('窄屏导航支持键盘、焦点归还和路由切换', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  const menuButton = page.getByRole('button', { name: '打开导航菜单', exact: true });
  const dialog = page.getByRole('dialog', { name: '工作区导航', exact: true });
  await expect(page.locator('nav[aria-label="主导航"]')).toBeHidden();

  await menuButton.click();
  await expect(dialog).toBeVisible();
  await expect(menuButton).toHaveAttribute('aria-expanded', 'true');
  await expect(dialog.getByRole('button', { name: '关闭导航菜单', exact: true })).toBeFocused();
  await expect.poll(() => dialog.evaluate((element) => element.contains(document.activeElement))).toBe(true);
  for (let step = 0; step < 8; step += 1) await page.keyboard.press('Tab');
  await expect.poll(() => dialog.evaluate((element) => element.contains(document.activeElement))).toBe(true);
  await expectNoHorizontalOverflow(page);
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(menuButton).toBeFocused();

  await menuButton.press('Enter');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('navigation', { name: '完整导航', exact: true })
    .getByRole('link', { name: '告警列表', exact: true }).click();
  await expect(page.getByRole('heading', { name: '告警列表', level: 1 })).toBeVisible();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole('main')).toBeFocused();
  await expectNoHorizontalOverflow(page);

  await menuButton.click();
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: '关闭导航菜单', exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect(menuButton).toBeFocused();
});
