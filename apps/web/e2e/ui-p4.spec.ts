import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import path from 'node:path';
import { expect, test, type Page, type Route } from '@playwright/test';

test.skip(process.env.EVIDENCESOC_P4_ACCEPTANCE !== '1', 'P4 正式开场检查仅在专用隔离配置中启用。');

const artifacts = path.resolve(__dirname, '../../../docs/ui-preview');
const webRequire = createRequire(path.resolve(__dirname, '../package.json'));
type FixturePage = { alerts: unknown[]; health: unknown; incidents: unknown[]; plans: unknown[];
  summary: (window?: string) => unknown; page: (items: unknown[], url: URL) => unknown };
const fixture = webRequire(path.join(artifacts, 'p2-fixtures.cjs')) as FixturePage;
const seenKey = 'evidencesoc.intro.seen.v1';
const seenCookie = 'evidencesoc_intro_seen';
type Audit = { writes: string[]; unknown: string[]; errors: string[] };
const audits = new WeakMap<Page, Audit>();

function opening(page: Page) { return page.getByTestId('opening-experience'); }
function digest(value: Buffer) { return createHash('sha256').update(value).digest('hex'); }
async function canvasDigest(page: Page, testId: string) {
  return digest(await page.getByTestId(testId).screenshot({ animations: 'allow' }));
}
async function resetFirstVisit(page: Page) {
  await page.context().clearCookies({ name: seenCookie });
  await page.addInitScript((key) => { try { sessionStorage.removeItem(key); } catch { /* defensive fixture reset */ } }, seenKey);
}
async function routeReadOnly(route: Route, audit: Audit) {
  const request = route.request(); const method = request.method(); const url = new URL(request.url());
  if (!['GET', 'HEAD'].includes(method)) { audit.writes.push(`${method} ${url.pathname}`); await route.fulfill({ status: 405, json: { error: { code: 'P4_WRITES_FORBIDDEN', message: 'P4 read-only fixture', trace_id: 'P4-ROUTE' } } }); return; }
  if (url.pathname === '/api/v1/dashboard/summary') { await route.fulfill({ json: fixture.summary(url.searchParams.get('window') ?? '24h') }); return; }
  if (url.pathname === '/api/v1/data-sources/health') { await route.fulfill({ json: fixture.health }); return; }
  if (url.pathname === '/api/v1/alerts') { await route.fulfill({ json: fixture.page(fixture.alerts, url) }); return; }
  if (url.pathname === '/api/v1/incidents') { await route.fulfill({ json: fixture.page(fixture.incidents, url) }); return; }
  if (url.pathname === '/api/v1/response-plans') { await route.fulfill({ json: fixture.page(fixture.plans, url) }); return; }
  if (url.pathname === '/api/v1/session' || url.pathname === '/api/v1/session/demo') { await route.fulfill({ status: 401, json: { error: { code: 'UNAUTHORIZED', message: 'P4 fixture has no identity', trace_id: 'P4-SESSION' } } }); return; }
  audit.unknown.push(`${method} ${url.pathname}`); await route.fulfill({ status: 404, json: { error: { code: 'P4_FIXTURE_NOT_FOUND', message: 'P4 route not provided', trace_id: 'P4-UNKNOWN' } } });
}
async function assertNoOverflow(page: Page) {
  const sizes = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth, body: document.body.scrollWidth }));
  expect(sizes.document).toBeLessThanOrEqual(sizes.viewport + 1); expect(sizes.body).toBeLessThanOrEqual(sizes.viewport + 1);
}

test.beforeEach(async ({ page }) => {
  const audit: Audit = { writes: [], unknown: [], errors: [] }; audits.set(page, audit);
  page.on('pageerror', (error) => audit.errors.push(error.message));
  await page.route('**/api/v1/**', (route) => routeReadOnly(route, audit));
});
test.afterEach(async ({ page }) => {
  const audit = audits.get(page); expect(audit?.writes ?? []).toEqual([]); expect(audit?.unknown ?? []).toEqual([]); expect(audit?.errors ?? []).toEqual([]);
});

test('P4 每次打开首页都展示正式开场，旧已看标记不再跳过', async ({ page }) => {
  await page.addInitScript((key) => { sessionStorage.setItem(key, '1'); }, seenKey);
  await page.setViewportSize({ width: 1690, height: 914 }); await page.goto('/');
  const dialog = opening(page);
  await expect(dialog).toBeVisible(); await expect(dialog).toHaveAttribute('role', 'dialog'); await expect(dialog).toHaveAttribute('aria-modal', 'true');
  await expect(dialog).toHaveAccessibleName('证链；让每一次安全判断，都有证据可循');
  await expect(dialog.getByRole('heading', { name: /证\s*链/ })).toBeVisible();
  await expect(dialog.getByText('让每一次安全判断，都有证据可循', { exact: true })).toBeVisible();
  await expect(dialog.getByText('证据驱动的安全调查与模拟响应', { exact: true })).toBeVisible();
  await expect(dialog).not.toContainText(/开场旋转|主体收束|工作台显露|WEBGL|REALTIME CORE|黑色舞台|独立.*预览|离线预览/);
  const particles = dialog.getByTestId('opening-particles'); await expect(particles).toHaveAttribute('data-particle-count', '180');
  await expect(particles).toHaveAttribute('data-particle-size-range', '.65-3.00');
  await expect(particles).toHaveAttribute('data-motion-state', 'running');
  const particleStart = await canvasDigest(page, 'opening-particles');
  await expect.poll(() => canvasDigest(page, 'opening-particles'), { timeout: 2500 }).not.toBe(particleStart);
  const core = dialog.getByTestId('opening-core'); await expect(core).toHaveAttribute('data-animation-speed', '1.8');
  await expect(core).toHaveAttribute('data-renderer-state', 'running');
  const coreStart = await canvasDigest(page, 'opening-core');
  await expect.poll(() => canvasDigest(page, 'opening-core'), { timeout: 2500 }).not.toBe(coreStart);
  await page.screenshot({ path: path.join(artifacts, 'p4-opening-desktop.png'), animations: 'allow' });
});

test('P4 进入后当前页面不重开，刷新首页重新展示且深链接不自动弹出', async ({ page }) => {
  await resetFirstVisit(page); await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/incidents'); await expect(opening(page)).toHaveCount(0);
  await page.goto('/');
  const dialog = opening(page); await dialog.getByRole('button', { name: '进入工作台', exact: true }).click();
  await expect(dialog).toHaveAttribute('data-state', 'leaving'); await expect(dialog).toHaveCount(0);
  await expect(page.locator('#soc-main')).toBeFocused();
  expect(await page.evaluate((key) => sessionStorage.getItem(key), seenKey)).toBeNull();
  expect((await page.context().cookies()).some((cookie) => cookie.name === seenCookie)).toBe(false);
  await expect(page.getByRole('heading', { name: '运营总览', exact: true })).toBeVisible();
  await page.screenshot({ path: path.join(artifacts, 'p4-workspace-after-opening.png'), fullPage: true, animations: 'disabled' });
  await expect(dialog).toHaveCount(0);
  await page.reload(); await expect(opening(page)).toBeVisible();
  await page.keyboard.press('Escape'); await expect(opening(page)).toHaveCount(0);
  await page.goto('/incidents');
  await expect(opening(page)).toHaveCount(0); await expect(page.getByRole('heading', { name: '调查列表', exact: true })).toBeVisible();
});

test('P4 可从真实外壳重播，并用跳过或 Escape 立即返回主内容', async ({ page }) => {
  await page.goto('/'); await expect(opening(page)).toBeVisible();
  await opening(page).getByRole('button', { name: '跳过开场', exact: true }).click(); await expect(opening(page)).toHaveCount(0);
  await page.getByRole('button', { name: '重播开场', exact: true }).click(); await expect(opening(page)).toBeVisible();
  await opening(page).getByRole('button', { name: '跳过开场', exact: true }).click(); await expect(opening(page)).toHaveCount(0); await expect(page.locator('#soc-main')).toBeFocused();
  await page.getByRole('button', { name: '重播开场', exact: true }).click(); await expect(opening(page)).toBeVisible();
  await page.keyboard.press('Escape'); await expect(opening(page)).toHaveCount(0); await expect(page.locator('#soc-main')).toBeFocused();
});

test('P4 模态开场将正反向 Tab 焦点约束在自身内部', async ({ page }) => {
  await resetFirstVisit(page); await page.goto('/'); const dialog = opening(page); await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('button', { name: '进入工作台', exact: true })).toBeFocused();
  for (const key of ['Tab', 'Tab', 'Shift+Tab', 'Shift+Tab']) {
    await page.keyboard.press(key);
    expect(await dialog.evaluate((node) => node.contains(document.activeElement))).toBe(true);
  }
  await page.keyboard.press('Escape'); await expect(dialog).toHaveCount(0);
});

test('P4 减少动态下保持静态，并可随系统偏好恢复', async ({ page }) => {
  await resetFirstVisit(page); await page.emulateMedia({ reducedMotion: 'reduce' }); await page.setViewportSize({ width: 1440, height: 1000 }); await page.goto('/');
  const dialog = opening(page); const particles = dialog.getByTestId('opening-particles'); const core = dialog.getByTestId('opening-core');
  await expect(particles).toHaveAttribute('data-motion-state', 'static'); await expect(core).toHaveAttribute('data-renderer-state', 'static');
  const firstParticle = await canvasDigest(page, 'opening-particles'); const firstCore = await canvasDigest(page, 'opening-core');
  await expect.poll(() => canvasDigest(page, 'opening-particles'), { timeout: 800 }).toBe(firstParticle);
  await expect.poll(() => canvasDigest(page, 'opening-core'), { timeout: 800 }).toBe(firstCore);
  await page.screenshot({ path: path.join(artifacts, 'p4-opening-reduced.png'), animations: 'disabled' });
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await expect(particles).toHaveAttribute('data-motion-state', 'running'); await expect(core).toHaveAttribute('data-renderer-state', 'running');
});

test('P4 WebGL2 不可用时显示静态核心且不阻断进入', async ({ page }) => {
  await resetFirstVisit(page);
  await page.addInitScript(() => {
    const original = HTMLCanvasElement.prototype.getContext;
    Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', { configurable: true, value(contextId: string, ...args: unknown[]) {
      if (contextId === 'webgl2') return null;
      return Reflect.apply(original, this, [contextId, ...args]);
    } });
  });
  await page.goto('/'); const dialog = opening(page);
  await expect(dialog.getByTestId('opening-core-fallback')).toBeVisible(); await expect(dialog.getByTestId('opening-core-fallback')).toHaveRole('img');
  await expect(dialog.getByTestId('opening-core-fallback')).toHaveAccessibleName('旋转的证据核心球体与关系轨道');
  await dialog.getByRole('button', { name: '进入工作台', exact: true }).click(); await expect(dialog).toHaveCount(0); await expect(page.locator('#soc-main')).toBeFocused();
});

test('P4 移动开场在 320–390px 使用 32 个静态粒子且无横向溢出', async ({ page }) => {
  await resetFirstVisit(page); await page.setViewportSize({ width: 390, height: 1080 }); await page.goto('/'); const dialog = opening(page);
  await expect(dialog).toBeVisible(); await expect(dialog.getByTestId('opening-particles')).toHaveAttribute('data-particle-count', '32');
  await expect(dialog.getByTestId('opening-particles')).toHaveAttribute('data-motion-state', 'static'); await assertNoOverflow(page);
  const title = dialog.getByRole('heading', { name: /证\s*链/ }); const box = await title.boundingBox();
  expect(box).not.toBeNull(); expect(box!.x).toBeGreaterThanOrEqual(-1); expect(box!.x + box!.width).toBeLessThanOrEqual(391);
  await page.screenshot({ path: path.join(artifacts, 'p4-opening-mobile.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 320, height: 760 }); await assertNoOverflow(page);
  await expect(dialog.getByRole('button', { name: '进入工作台', exact: true })).toBeVisible(); await expect(dialog.getByRole('button', { name: '跳过开场', exact: true })).toBeVisible();
});
