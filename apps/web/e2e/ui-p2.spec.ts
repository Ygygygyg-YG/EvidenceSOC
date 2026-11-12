import { expect, test, type Page } from '@playwright/test';
import { routeReadOnly, type FixtureAudit } from './fixtures/readOnlyRoutes';

test.skip(process.env.EVIDENCESOC_P2_ACCEPTANCE !== '1', 'P2 视觉验收只在专用只读样例配置下运行，不对真实后端假定固定数量。');

const pageErrors = new WeakMap<Page, string[]>();
const fixtureAudits = new WeakMap<Page, FixtureAudit>();

test.beforeEach(async ({ page }) => {
  const audit = { writes: [], unknown: [] };
  fixtureAudits.set(page, audit);
  await page.route('**/api/v1/**', (route) => routeReadOnly(route, audit));
  const errors: string[] = [];
  pageErrors.set(page, errors);
  page.on('pageerror', (error) => errors.push(error.message));
});
test.afterEach(({ page }) => {
  expect(pageErrors.get(page)).toEqual([]);
  expect(fixtureAudits.get(page)).toEqual({ writes: [], unknown: [] });
});

async function noOverflow(page: Page) {
  const size = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth, body: document.body.scrollWidth }));
  expect(size.document).toBeLessThanOrEqual(size.viewport);
  expect(size.body).toBeLessThanOrEqual(size.viewport);
}
async function overview(page: Page) {
  await page.goto('/');
  const opening = page.getByTestId('opening-experience');
  await expect(opening).toBeVisible();
  await opening.getByRole('button', { name: '跳过开场', exact: true }).click();
  await expect(opening).toHaveCount(0);
  await expect(page.getByTestId('overview-metrics').getByText('68', { exact: true })).toBeVisible();
}
async function pixels(page: Page) {
  return page.getByTestId('particle-background').evaluate((canvas) => (canvas as HTMLCanvasElement).toDataURL());
}

test('P2 正式工作台黑色主题与语义色桥接，无预览开场文案', async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await overview(page);
  const theme = await page.evaluate(() => {
    const style = getComputedStyle(document.documentElement);
    return Object.fromEntries(['canvas', 'surface', 'elevated', 'text', 'primary', 'error', 'warning', 'success', 'primary-hover', 'primary-active']
      .map((name) => [name, style.getPropertyValue(`--soc-${name}`).trim()]));
  });
  expect(theme.canvas.toUpperCase()).toBe('#020304');
  expect(theme.surface.toUpperCase()).toBe('#090C0F');
  expect(theme.primary.toUpperCase()).toBe('#9BDDDD');
  for (const color of ['error', 'warning', 'success', 'primary-hover', 'primary-active']) expect(theme[color]).toMatch(/^#[0-9a-f]{6}$/i);
  await expect(page.locator('#intro')).toHaveCount(0);
  await expect(page.getByRole('main')).not.toContainText('独立可播放预览');
  await expect(page.getByRole('main')).not.toContainText('WEBGL 2 / REALTIME CORE');
  await noOverflow(page);
  await page.screenshot({ path: test.info().outputPath('p2-overview-desktop.png'), fullPage: true });
});

test('P2 中文宽侧栏与四个真实列表在 320–1920px 无横向溢出', async ({ page }) => {
  test.setTimeout(90000);
  for (const width of [1920, 1440, 1024, 768, 767, 390, 320]) {
    await page.setViewportSize({ width, height: width < 768 ? 844 : 1080 });
    for (const [url, heading] of [['/', '运营总览'], ['/alerts', '告警列表'], ['/incidents', '调查列表'], ['/responses', '响应审批']]) {
      await page.goto(url);
      await expect(page.getByRole('heading', { name: heading, level: 1 })).toBeVisible();
      if (url === '/') await expect(page.getByTestId('overview-metrics')).toBeVisible();
      else await expect(page.getByTestId(url === '/alerts' ? 'alerts-total' : url === '/incidents' ? 'incidents-total' : 'responses-total')).toBeVisible();
      await noOverflow(page);
      const menu = page.getByRole('button', { name: '打开导航菜单', exact: true });
      if (width < 768) await expect(menu).toBeVisible();
      else {
        await expect(menu).toBeHidden();
        const navigation = page.getByRole('navigation', { name: '主导航', exact: true });
        for (const title of ['运营总览', '告警列表', '调查列表', '响应审批']) await expect(navigation.getByRole('link', { name: title, exact: true })).toBeVisible();
        const titleBox = await page.getByRole('heading', { name: heading, level: 1 }).boundingBox();
        expect(titleBox?.x).toBeGreaterThanOrEqual(width >= 1024 ? 240 : 200);
      }
      if (width === 1920 && url !== '/') await page.screenshot({ path: test.info().outputPath(`p2-${url.slice(1)}-desktop.png`), fullPage: true });
      if (width === 390 && url === '/') await page.screenshot({ path: test.info().outputPath('p2-overview-mobile.png'), fullPage: true });
      if (width === 390 && url === '/alerts') await page.screenshot({ path: test.info().outputPath('p2-alerts-mobile.png'), fullPage: true });
      if (width === 1440 && url === '/') await page.screenshot({ path: test.info().outputPath('p2-overview-1440.png'), fullPage: true });
    }
  }
});

test('P2 背景可暂停恢复，隐藏时停止，减少动态下保持静态', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await overview(page);
  const canvas = page.getByTestId('particle-background');
  await expect(canvas).toHaveAttribute('data-motion-state', 'running');
  await expect(canvas).toHaveAttribute('data-particle-count', '96');
  await expect(canvas).toHaveAttribute('data-particle-size-range', '.55-2.40');
  const moving = await pixels(page);
  await expect.poll(() => pixels(page)).not.toBe(moving);
  await page.getByRole('button', { name: '暂停背景动效', exact: true }).click();
  await expect(canvas).toHaveAttribute('data-motion-state', 'paused');
  const paused = await pixels(page);
  await page.waitForTimeout(180);
  expect(await pixels(page)).toBe(paused);
  await page.getByRole('button', { name: '恢复背景动效', exact: true }).click();
  await expect(canvas).toHaveAttribute('data-motion-state', 'running');
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => true });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect(canvas).toHaveAttribute('data-motion-state', 'paused');
  const hidden = await pixels(page);
  await page.waitForTimeout(180);
  expect(await pixels(page)).toBe(hidden);
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => false });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect(canvas).toHaveAttribute('data-motion-state', 'running');
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await expect(canvas).toHaveAttribute('data-motion-state', 'static');
  const reduced = await pixels(page);
  await page.waitForTimeout(180);
  expect(await pixels(page)).toBe(reduced);
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await expect(canvas).toHaveAttribute('data-motion-state', 'running');
});

test('P2 高 DPI 不超过 1.5，小屏只绘制静态轻量粒子', async ({ browser, page, baseURL }) => {
  const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, reducedMotion: 'reduce' });
  const audit = { writes: [], unknown: [] };
  try {
    await context.route('**/api/v1/**', (route) => routeReadOnly(route, audit));
    const highDpi = await context.newPage();
    await overview(highDpi);
    const size = await highDpi.getByTestId('particle-background').evaluate((element) => ({
      pixel: (element as HTMLCanvasElement).width,
      css: element.getBoundingClientRect().width,
    }));
    expect(size.pixel / size.css).toBeLessThanOrEqual(1.501);
    expect(audit).toEqual({ writes: [], unknown: [] });
  } finally {
    await context.close();
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await overview(page);
  await expect(page.getByTestId('particle-background')).toHaveAttribute('data-motion-state', 'static');
  await expect(page.getByTestId('particle-background')).toHaveAttribute('data-particle-count', '24');
  await expect(page.getByTestId('particle-background')).toHaveAttribute('data-particle-size-range', '.55-2.40');
});
