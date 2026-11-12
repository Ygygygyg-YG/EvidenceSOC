import { expect, test, type Locator, type Page } from '@playwright/test';
import path from 'node:path';
import { createRequire } from 'node:module';
import { GRAPH_NODE_HEIGHT, GRAPH_NODE_WIDTH } from '../src/features/incidents/graphLayout';
import { incidentSummarySchema, type IncidentSummary } from '../src/features/incidents/incidentContract';
import { investigationSnapshotSchema, type InvestigationSnapshot } from '../src/features/incidents/investigationSnapshotContract';
import { evidenceDetailSchema, type EvidenceDetail } from '../src/features/incidents/evidenceDetailContract';
import { evidencePageSchema, type EvidencePage } from '../src/features/incidents/evidencePageContract';
import { demoSessionSchema, type DemoSession } from '../src/features/responses/sessionContract';
import type { DashboardData, DashboardWindow, SourceHealthData } from '../src/features/dashboard/dashboardContract';

test.skip(process.env.EVIDENCESOC_P3_ACCEPTANCE !== '1', 'P3 视觉检查仅在专用隔离配置中启用，不使用真实业务后端。');

const webRequire = createRequire(path.resolve(__dirname, '../package.json'));
type P3Fixtures = {
  incidentId: string; investigationId: string; stepIds: string[]; evidenceIds: string[];
  incident: IncidentSummary; snapshot: InvestigationSnapshot;
  noRelationships: InvestigationSnapshot; missingMetadata: InvestigationSnapshot;
  evidenceDetails: Record<string, EvidenceDetail>;
  evidencePage: (page?: number, pageSize?: number) => EvidencePage;
  session: DemoSession; health: SourceHealthData; summary: (window?: DashboardWindow) => DashboardData;
};
const fixtures = webRequire(path.resolve(__dirname, 'fixtures/p3-fixtures.cjs')) as P3Fixtures;
type Audit = {
  snapshot: InvestigationSnapshot;
  writes: string[]; unknownGets: string[]; streams: string[]; errors: string[];
};
const audits = new WeakMap<Page, Audit>();
function auditFor(page: Page): Audit {
  const audit = audits.get(page);
  if (!audit) throw new Error('P3 route audit is not installed');
  return audit;
}
function attackRegion(page: Page): Locator { return page.getByRole('region', { name: '攻击链', exact: true }); }
function stepButton(page: Page, sequence: number): Locator {
  // getByRole excludes the graph retained under display:none when the stage list is selected.
  return attackRegion(page).getByRole('button', { name: new RegExp(`^第 ${sequence} 步 `) });
}
async function openWorkbench(page: Page, width = 1920) {
  await page.setViewportSize({ width, height: 1080 });
  await page.goto(`/incidents/${fixtures.incidentId}`);
  await expect(page.getByRole('heading', { name: '案件详情', exact: true })).toBeVisible();
  await expect(attackRegion(page).getByRole('button', { name: /^第 [1-4] 步 / })).toHaveCount(4);
  await expect(stepButton(page, 3)).toHaveAttribute('data-support-status', 'candidate');
  // Evidence and run details stay out of the document flow until their drawer is opened.
  await expect(page.getByRole('region', { name: '证据检查器', exact: true })).toHaveCount(0);
}
async function screenshot(page: Page, name: string, fullPage = true) {
  await page.screenshot({ path: test.info().outputPath(name), fullPage, animations: 'disabled' });
}
async function assertNoOverflow(page: Page) {
  const size = await page.evaluate(() => ({
    width: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(size.document).toBeLessThanOrEqual(size.width + 1);
  expect(size.body).toBeLessThanOrEqual(size.width + 1);
}

test.beforeAll(() => {
  incidentSummarySchema.parse(fixtures.incident);
  for (const snapshot of [fixtures.snapshot, fixtures.noRelationships, fixtures.missingMetadata]) {
    investigationSnapshotSchema.parse(snapshot);
    expect(snapshot.status).toBe('completed');
  }
  evidencePageSchema.parse(fixtures.evidencePage(1, 20));
  demoSessionSchema.parse(fixtures.session);
  for (const detail of Object.values(fixtures.evidenceDetails)) {
    evidenceDetailSchema.parse(detail);
    expect(detail.integrity.status).toBe('unavailable');
    expect(detail.integrity.calculated_sha256).toBeNull();
  }
});

test.beforeEach(async ({ page }) => {
  const audit: Audit = { snapshot: fixtures.snapshot, writes: [], unknownGets: [], streams: [], errors: [] };
  audits.set(page, audit);
  page.on('pageerror', (error) => audit.errors.push(error.message));
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    if (method !== 'GET' && method !== 'HEAD') {
      audit.writes.push(`${method} ${url.pathname}`);
      await route.fulfill({ status: 405, json: { error: { code: 'P3_READ_ONLY', message: 'Read-only visual fixture', trace_id: 'TRACE-P3' } } });
      return;
    }
    let body: unknown;
    if (url.pathname === `/api/v1/incidents/${fixtures.incidentId}`) body = audit.snapshot;
    else if (url.pathname === `/api/v1/investigations/${fixtures.investigationId}`) body = audit.snapshot;
    else if (url.pathname === `/api/v1/incidents/${fixtures.incidentId}/evidence`) {
      body = fixtures.evidencePage(Number(url.searchParams.get('page') ?? 1), Number(url.searchParams.get('page_size') ?? 20));
    } else if (url.pathname.startsWith(`/api/v1/incidents/${fixtures.incidentId}/evidence/`)) {
      body = fixtures.evidenceDetails[decodeURIComponent(url.pathname.split('/').at(-1) ?? '')];
    } else if (url.pathname === '/api/v1/session') body = fixtures.session;
    else if (url.pathname === '/api/v1/dashboard/summary') {
      const value = url.searchParams.get('window');
      body = fixtures.summary(value === '1h' || value === '7d' ? value : '24h');
    } else if (url.pathname === '/api/v1/data-sources/health') body = fixtures.health;
    if (url.pathname.endsWith('/stream')) audit.streams.push(url.pathname);
    if (body === undefined) {
      audit.unknownGets.push(`${method} ${url.pathname}`);
      await route.fulfill({ status: 404, json: { error: { code: 'P3_UNMOCKED_GET', message: 'No fixture for this request', trace_id: 'TRACE-P3' } } });
    } else await route.fulfill({ json: body });
  });
});

test.afterEach(async ({ page }) => {
  const audit = auditFor(page);
  expect(audit.writes, 'P3 visual checks must not send business writes').toEqual([]);
  expect(audit.unknownGets, 'Every P3 API read must be explicitly mocked').toEqual([]);
  expect(audit.streams, 'Completed snapshots must not imply real native SSE acceptance').toEqual([]);
  expect(audit.errors, 'P3 application page errors').toEqual([]);
});

test('P3 球形节点匹配布局尺寸，三类关系保留方向与支持语义', async ({ page }) => {
  await openWorkbench(page);
  const graph = page.getByTestId('attack-graph');
  await expect(graph).toBeVisible();
  const nodes = graph.getByRole('button', { name: /^第 [1-4] 步 / });
  await expect(nodes).toHaveCount(4);
  await expect(graph.getByTestId('step-sphere')).toHaveCount(4);
  for (let index = 0; index < 4; index += 1) {
    const node = nodes.nth(index);
    await expect(node).toHaveAttribute('data-node-kind', 'sphere');
    await expect(node).toHaveAttribute('data-step-id', fixtures.stepIds[index]);
    await expect(node.getByTestId('step-sphere')).toHaveAttribute('aria-hidden', 'true');
    const dimensions = await node.evaluate((button) => {
      const wrapper = button.closest<HTMLElement>('.react-flow__node');
      if (!(button instanceof HTMLButtonElement) || !wrapper) throw new Error('Missing ReactFlow node wrapper');
      const buttonBox = button.getBoundingClientRect();
      const wrapperBox = wrapper.getBoundingClientRect();
      // Check text-bearing metadata, not radial decoration or a container's shadow extents.
      const metadata = [...button.querySelectorAll<HTMLElement>('strong, span, time, small')]
        .filter((element) => !element.closest('[aria-hidden="true"]') &&
          [...element.childNodes].some((child) => child.nodeType === Node.TEXT_NODE && Boolean(child.textContent?.trim())));
      return {
        buttonWidth: button.offsetWidth, buttonHeight: button.offsetHeight,
        wrapperWidth: wrapper.offsetWidth, wrapperHeight: wrapper.offsetHeight,
        scaledWidthDelta: Math.abs(buttonBox.width - wrapperBox.width),
        scaledHeightDelta: Math.abs(buttonBox.height - wrapperBox.height),
        metadataFits: metadata.every((element) => {
          const rect = element.getBoundingClientRect();
          return element.scrollWidth <= element.clientWidth + 1 &&
            rect.left >= buttonBox.left - 1 && rect.right <= buttonBox.right + 1 &&
            rect.top >= buttonBox.top - 1 && rect.bottom <= buttonBox.bottom + 1;
        }),
      };
    });
    expect(dimensions.buttonWidth).toBe(GRAPH_NODE_WIDTH);
    expect(dimensions.buttonHeight).toBe(GRAPH_NODE_HEIGHT);
    expect(dimensions.wrapperWidth).toBe(GRAPH_NODE_WIDTH);
    expect(dimensions.wrapperHeight).toBe(GRAPH_NODE_HEIGHT);
    expect(dimensions.scaledWidthDelta).toBeLessThanOrEqual(1);
    expect(dimensions.scaledHeightDelta).toBeLessThanOrEqual(1);
    expect(dimensions.metadataFits).toBe(true);
  }
  await expect(stepButton(page, 3)).toHaveAttribute('data-support-status', 'candidate');
  await expect(stepButton(page, 3)).toContainText('候选步骤 · 待证实');
  await expect(stepButton(page, 4)).toHaveAttribute('data-support-status', 'insufficient');
  await expect(stepButton(page, 4)).toContainText('证据引用不足');
  await expect(graph.locator('.react-flow__edge')).toHaveCount(3);
  const temporal = graph.locator('[aria-label^="时间先后："]');
  const candidate = graph.locator('[aria-label^="因果候选："]');
  const related = graph.locator('[aria-label^="行为关联："]');
  await expect(temporal).toHaveCount(1);
  await expect(temporal).toHaveAttribute('aria-label', /STEP-P3-1 早于 STEP-P3-2/);
  await expect(temporal.locator('.react-flow__edge-path')).toHaveAttribute('marker-end', /arrowclosed/);
  expect(await temporal.locator('.react-flow__edge-path').evaluate((element) => (element as SVGPathElement).style.strokeDasharray)).toBe('');
  await expect(candidate).toHaveCount(1);
  await expect(candidate).toHaveAttribute('aria-label', /STEP-P3-2 可能导致 STEP-P3-3.*待证实/);
  await expect(candidate).toContainText('因果候选');
  await expect(candidate).toContainText('待证实');
  await expect(candidate.locator('.react-flow__edge-path')).toHaveAttribute('marker-end', /arrowclosed/);
  expect(await candidate.locator('.react-flow__edge-path').evaluate((element) => (element as SVGPathElement).style.strokeDasharray)).toBe('6, 4');
  await expect(related).toHaveCount(1);
  await expect(related).toHaveAttribute('aria-label', /STEP-P3-3 与 STEP-P3-4，方向未定义.*证据不足/);
  await expect(related).toContainText('行为关联');
  await expect(related.locator('.react-flow__edge-path')).not.toHaveAttribute('marker-end', /./);
  expect(await related.locator('.react-flow__edge-path').evaluate((element) => (element as SVGPathElement).style.strokeDasharray)).toBe('2, 4');
  await assertNoOverflow(page);
  await screenshot(page, 'p3-workbench-desktop.png');
});

test('P3 图谱按钮支持 Enter 与 Space，证据联动只展示引用且不伪造哈希通过', async ({ page }) => {
  await openWorkbench(page);
  await stepButton(page, 3).click();
  const drawer = page.getByRole('dialog', { name: '证据检查器', exact: true });
  const inspector = drawer.getByRole('region', { name: '证据检查器', exact: true });
  await expect(inspector).toContainText('步骤输出置信度 47%');
  await expect(inspector).toContainText('候选步骤 · 待证实');
  await expect(inspector).toContainText('计算依据未提供');
  await drawer.getByRole('button', { name: '关闭', exact: true }).click();
  const first = stepButton(page, 1);
  await first.focus();
  await expect(first).toBeFocused();
  await first.press('Enter');
  await expect(first).toHaveAttribute('aria-pressed', 'true');
  await drawer.getByRole('button', { name: '关闭', exact: true }).click();
  const second = stepButton(page, 2);
  await second.focus();
  await second.press('Space');
  await expect(second).toHaveAttribute('aria-pressed', 'true');
  await expect(first).toHaveAttribute('aria-pressed', 'false');
  await expect(inspector).toContainText('app-01 / shell');
  await expect(inspector).toContainText('步骤输出置信度 82%');
  await expect(inspector).not.toContainText('edge-origin-only');
  await expect(inspector.getByRole('button', { name: /入口请求日志/ })).toHaveCount(0);
  await expect(inspector.getByRole('button', { name: /凭据访问线索/ })).toHaveCount(0);
  await inspector.getByRole('button', { name: /进程执行记录/ }).click();
  await expect(inspector).toContainText('"synthetic": true');
  await expect(inspector).toContainText('P3 visual fixture; not a production event.');
  await expect(inspector).toContainText('PostgreSQL 本次校验不可用');
  await expect(inspector).not.toContainText('本次校验通过');
  await expect(second).toHaveAttribute('aria-pressed', 'true');
  await screenshot(page, 'p3-evidence-inspector-desktop.png');
});

test('P3 阶段过滤不创造边，重新布局与切换视图保留步骤选择', async ({ page }) => {
  await openWorkbench(page);
  await stepButton(page, 2).click();
  await page.getByRole('dialog', { name: '证据检查器', exact: true }).getByRole('button', { name: '关闭', exact: true }).click();
  const attack = attackRegion(page);
  await attack.getByRole('combobox', { name: '阶段', exact: true }).selectOption('execution');
  await expect(attack.getByRole('button', { name: /^第 [1-4] 步 / })).toHaveCount(1);
  await expect(stepButton(page, 2)).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByTestId('attack-graph').locator('.react-flow__edge')).toHaveCount(0);
  await attack.getByRole('button', { name: '重新布局', exact: true }).click();
  await expect(stepButton(page, 2)).toHaveAttribute('aria-pressed', 'true');
  await attack.getByRole('combobox', { name: '阶段', exact: true }).selectOption('all');
  await expect(attack.getByRole('button', { name: /^第 [1-4] 步 / })).toHaveCount(4);
  await expect(page.getByTestId('attack-graph').locator('.react-flow__edge')).toHaveCount(3);
  await attack.getByRole('button', { name: '阶段列表', exact: true }).click();
  await expect(stepButton(page, 2)).toHaveAttribute('data-node-kind', 'stage');
  await expect(stepButton(page, 2)).toHaveAttribute('aria-pressed', 'true');
  await expect(stepButton(page, 2)).toContainText('步骤输出置信度 82%');
  await attack.getByRole('button', { name: '图谱', exact: true }).click();
  await expect(stepButton(page, 2)).toHaveAttribute('data-node-kind', 'sphere');
  await expect(stepButton(page, 2)).toHaveAttribute('aria-pressed', 'true');
});

test('P3 未提供关系或元数据时保持未知，不把序号画成关系或补全实体概率', async ({ page }) => {
  auditFor(page).snapshot = fixtures.noRelationships;
  await openWorkbench(page);
  await expect(page.getByTestId('attack-graph').locator('.react-flow__edge')).toHaveCount(0);
  await expect(attackRegion(page)).toContainText('关系未知');
  await expect(attackRegion(page)).toContainText('序号仅用于排列');
  auditFor(page).snapshot = fixtures.missingMetadata;
  await page.reload();
  const third = stepButton(page, 3);
  await expect(third).toHaveAttribute('data-support-status', 'candidate');
  await expect(third).toContainText('阶段未提供');
  await expect(third).toContainText('主机未提供 / 服务未提供');
  await expect(third).toContainText('技术未提供');
  await expect(third).toContainText('置信度未提供');
  await expect(third).toContainText('2026/11/04 11:23:00');
  await expect(third).not.toContainText('47%');
  await expect(third).not.toContainText('edge-origin-only');
  await expect(page.getByTestId('attack-graph').locator('.react-flow__edge')).toHaveCount(0);
  await attackRegion(page).getByRole('button', { name: '阶段列表', exact: true }).click();
  await expect(stepButton(page, 3)).toContainText('置信度未提供');
  await expect(stepButton(page, 3)).toContainText('2026/11/04 11:23:00');
  await screenshot(page, 'p3-metadata-unknown.png');
});

test('P3 工作台在 320–1920px 无横向溢出，中屏及小屏证据抽屉保留选中状态', async ({ page }) => {
  test.setTimeout(90000);
  for (const width of [320, 390, 767, 768, 1024, 1440, 1920]) {
    await openWorkbench(page, width);
    await assertNoOverflow(page);
    if (width === 1440) {
      await screenshot(page, 'p3-workbench-1440.png');
      await stepButton(page, 2).click();
      const drawer = page.getByRole('dialog', { name: '证据检查器', exact: true });
      await expect(drawer).toBeVisible();
      await expect(drawer).toContainText('app-01 / shell');
      await drawer.getByRole('button', { name: /进程执行记录/ }).click();
      await expect(drawer).toContainText('PostgreSQL 本次校验不可用');
      await screenshot(page, 'p3-evidence-drawer-1440.png', false);
      await assertNoOverflow(page);
      await drawer.getByRole('button', { name: '关闭', exact: true }).click();
      await expect(drawer).toBeHidden();
      await expect(stepButton(page, 2)).toHaveAttribute('aria-pressed', 'true');
    }
    if (width === 390) {
      await expect(attackRegion(page).getByRole('button', { name: '阶段列表', exact: true })).toHaveAttribute('aria-pressed', 'true');
      await expect(stepButton(page, 2)).toHaveAttribute('data-node-kind', 'stage');
      await screenshot(page, 'p3-stage-list-mobile.png');
      await stepButton(page, 2).click();
      const drawer = page.getByRole('dialog', { name: '证据检查器', exact: true });
      await expect(drawer).toBeVisible();
      await expect(drawer).toContainText('第 2 步引用的证据');
      await expect(drawer).toContainText('进程执行记录');
      await screenshot(page, 'p3-evidence-drawer-mobile.png', false);
      await assertNoOverflow(page);
      await drawer.getByRole('button', { name: '关闭', exact: true }).click();
      await expect(drawer).toBeHidden();
      await expect(stepButton(page, 2)).toHaveAttribute('aria-pressed', 'true');
    }
  }
});

test('P5 证据概览与运行记录使用侧边抽屉且不增加主页面高度', async ({ page }) => {
  await openWorkbench(page, 1440);
  const progress = page.getByRole('region', { name: '六角色进度', exact: true });
  const runTrigger = progress.getByRole('button', { name: /查看.+运行记录/ }).first();
  await expect(runTrigger).toBeVisible();
  const baselineHeight = await page.evaluate(() => document.documentElement.scrollHeight);
  await runTrigger.click();
  const runDrawer = page.getByRole('dialog', { name: '运行记录', exact: true });
  await expect(runDrawer).toBeVisible();
  await expect(runDrawer.getByRole('region', { name: /运行记录$/ })).toContainText('仅展示后端返回的真实运行时间');
  expect(await page.evaluate(() => document.documentElement.scrollHeight)).toBe(baselineHeight);
  await screenshot(page, 'p5-run-records-drawer.png', false);
  await runDrawer.getByRole('button', { name: '关闭', exact: true }).click();
  await expect(runTrigger).toBeFocused();

  await page.getByRole('button', { name: /打开证据概览/ }).click();
  const evidenceDrawer = page.getByRole('dialog', { name: '证据检查器', exact: true });
  await expect(evidenceDrawer).toBeVisible();
  await expect(evidenceDrawer.getByRole('region', { name: '证据检查器', exact: true })).toContainText('当前案件已收集证据');
  expect(await page.evaluate(() => document.documentElement.scrollHeight)).toBe(baselineHeight);
  await screenshot(page, 'p5-evidence-overview-drawer.png', false);
});

test('P3 减少动态偏好下球形节点不运行持续 CSS 动画，装饰不进入无障碍树', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await openWorkbench(page);
  const graph = page.getByTestId('attack-graph');
  for (const sphere of await graph.getByTestId('step-sphere').all()) {
    await expect(sphere).toHaveAttribute('aria-hidden', 'true');
  }
  const continuous = await graph.locator('[data-node-kind="sphere"]').evaluateAll((buttons) => {
    const failures: string[] = [];
    for (const button of buttons) {
      // Deliberately inspect only nodes; P2 application's background Canvas is unrelated.
      for (const element of [button, ...button.querySelectorAll('*')]) {
        for (const pseudo of [null, '::before', '::after']) {
          const style = getComputedStyle(element, pseudo);
          const names = style.animationName.split(',').map((item) => item.trim());
          const iterations = style.animationIterationCount.split(',').map((item) => item.trim());
          const durations = style.animationDuration.split(',').map((item) => Number.parseFloat(item));
          names.forEach((name, index) => {
            const iteration = iterations[index % iterations.length];
            const duration = durations[index % durations.length];
            if (name !== 'none' && iteration === 'infinite' && duration > 0) failures.push(`${button.getAttribute('data-step-id')}:${name}:${pseudo ?? 'self'}`);
          });
        }
      }
    }
    return failures;
  });
  expect(continuous).toEqual([]);
  await expect(graph.getByTestId('step-sphere')).toHaveCount(4);
});
