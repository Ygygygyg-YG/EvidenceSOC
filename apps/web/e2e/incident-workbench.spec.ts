import { expect, test } from '@playwright/test';
import type { components } from '../src/lib/api/generated';

type IncidentDetail = components['schemas']['IncidentDetail'];

const incident: IncidentDetail = {
  incident_id: 'IN-WORKBENCH', alert_id: 'AL-WORKBENCH', status: 'awaiting_approval',
  created_at: '2026-09-21T10:20:24Z', investigation_id: 'IV-WORKBENCH', trace_id: 'TRACE-WORKBENCH',
  alerts: [{ alert_id: 'AL-WORKBENCH', title: 'SQL 注入演示告警', severity: 'high',
    created_at: '2026-09-21T10:20:24Z', event_ids: ['EVT-1', 'EVT-2'] }],
  evidence: [
    { evidence_id: 'EV-01K5TESTTESTTESTTESTTESTTEST', event_id: 'EVT-1', source: 'nginx',
      observed_at: '2026-09-21T10:20:24Z', query: { filters: { event_id: 'EVT-1' } },
      summary: '入口请求日志', content_sha256: 'a'.repeat(64) },
    { evidence_id: 'EV-01K5TESTTESTTESTTESTTESTTESU', event_id: 'EVT-2', source: 'waf',
      observed_at: '2026-09-21T10:21:24Z', query: { filters: { event_id: 'EVT-2' } },
      summary: '规则命中记录', content_sha256: 'b'.repeat(64) },
  ],
  knowledge: [],
  attack_steps: [
    { attack_step_id: 'STEP-1', sequence: 1, phase: 'initial_access', technique_id: 'T1190',
      description: '外部应用访问异常', occurred_at: '2026-09-21T10:20:24Z',
      evidence_ids: ['EV-01K5TESTTESTTESTTESTTESTTEST'], incident_id: 'IN-WORKBENCH' },
    { attack_step_id: 'STEP-2', sequence: 2, phase: 'execution', technique_id: null,
      description: '可疑请求被规则捕获', occurred_at: '2026-09-21T10:21:24Z',
      evidence_ids: ['EV-01K5TESTTESTTESTTESTTESTTESU'], incident_id: 'IN-WORKBENCH' },
  ],
  runs: [
    { run_id: 'RUN-1', incident_id: 'IN-WORKBENCH', agent_name: 'triage', status: 'completed',
      started_at: '2026-09-21T10:20:24Z', finished_at: '2026-09-21T10:20:54Z', evidence_ids: [] },
    { run_id: 'RUN-2', incident_id: 'IN-WORKBENCH', agent_name: 'collect', status: 'running',
      started_at: '2026-09-21T10:21:00Z', finished_at: null, evidence_ids: ['EV-01K5TESTTESTTESTTESTTESTTESU'] },
  ],
  origin: { observed_source_ip: '198.51.100.9', entry_host: 'edge-01', entry_service: 'nginx',
    first_seen_at: '2026-09-21T10:20:24Z', source_scope: 'external', confidence: 0.7,
    evidence_ids: ['EV-01K5TESTTESTTESTTESTTESTTEST'] },
  classification: { primary_type: 'sql_injection', attack_types: ['sql_injection'], attack_phase: 'initial_access',
    technique_ids: ['T1190'], confidence: 0.8, evidence_ids: ['EV-01K5TESTTESTTESTTESTTESTTEST'] },
  response_plan: null, approval: null, validation_result: null, simulation: [],
  fallback_used: false, errors: [], stop_reason: null,
};

const evidenceDetail = {
  evidence: { ...incident.evidence[1], incident_id: 'IN-WORKBENCH' },
  raw_event: { event_id: 'EVT-2', source: 'waf', observed_at: '2026-09-21T10:21:24Z',
    severity: 'high', event_type: 'waf_alert', raw: { request_path: '/login', rule: 'sqli' },
    content_sha256: 'b'.repeat(64) },
  raw_access: 'full',
  integrity: { algorithm: 'sha256', canonicalization: 'evidencesoc-json-v1', scope: 'postgresql',
    status: 'verified', checked_at: '2026-09-21T10:22:24Z', calculated_sha256: 'b'.repeat(64),
    stored_event_sha256: 'b'.repeat(64), stored_evidence_sha256: 'b'.repeat(64) },
};

function snapshotWithEdge(relation: string, supportStatus: 'supported' | 'candidate' | 'insufficient' = 'supported') {
  return {
    ...incident, revision: '4', stream_cursor: '3', updated_at: '2026-09-21T10:22:24Z',
    mode: 'rules', available_actions: [],
    attack_graph: {
      revision: '4', generated_at: '2026-09-21T10:22:24Z',
      nodes: incident.attack_steps.map((step) => ({
        step_id: step.attack_step_id, sequence: step.sequence, phase: step.phase,
        description: step.description, host: null, service: null, observed_at: step.occurred_at,
        technique_ids: step.technique_id ? [step.technique_id] : [], confidence: null,
        evidence_ids: step.evidence_ids, support_status: 'supported',
      })),
      edges: [{ edge_id: 'EDGE-1', source_step_id: 'STEP-1', target_step_id: 'STEP-2',
        relation, description: '调查快照提供的关系', confidence: null,
        evidence_ids: incident.evidence.map((item) => item.evidence_id), support_status: supportStatus }],
    },
  };
}

test.beforeEach(async ({ page }) => {
  await page.route('**/api/v1/session', (route) => route.fulfill({ json: {
    actor_id: 'demo-reviewer', role: 'reviewer', allowed_actions: ['approve', 'reject'], expires_at: '2030-01-01T00:00:00Z',
  } }));
  await page.route('**/api/v1/incidents/IN-WORKBENCH', (route) => route.fulfill({ json: incident }));
  await page.route('**/api/v1/incidents/IN-WORKBENCH/evidence?**', (route) => route.fulfill({ json: {
    items: incident.evidence.map((item) => ({ ...item, incident_id: incident.incident_id })),
    total: incident.evidence.length, page: 1, page_size: 20,
  } }));
});

test('证据按服务端总数分页，能继续加载快照之外的证据', async ({ page }) => {
  const evidenceItems = Array.from({ length: 21 }, (_, index) => ({
    ...incident.evidence[0], incident_id: incident.incident_id,
    evidence_id: `EV-PAGE-${index + 1}`, event_id: `EVT-PAGE-${index + 1}`,
    summary: index === 20 ? '尾页新增证据' : `分页证据 ${index + 1}`,
  }));
  await page.route('**/api/v1/incidents/IN-WORKBENCH/evidence?**', (route) => {
    const requestedPage = Number(new URL(route.request().url()).searchParams.get('page'));
    return route.fulfill({ json: {
      items: requestedPage === 1 ? evidenceItems.slice(0, 20) : evidenceItems.slice(20),
      total: 21, page: requestedPage, page_size: 20,
    } });
  });
  await page.setViewportSize({ width: 1920, height: 1000 });
  await page.goto('/incidents/IN-WORKBENCH');
  await expect(page.getByText('分页证据 20')).toHaveCount(0);
  await page.getByRole('button', { name: '打开证据概览，共 21 条' }).click();
  const drawer = page.getByRole('dialog', { name: '证据检查器' });
  const inspector = drawer.getByRole('region', { name: '证据检查器' });
  await expect(inspector.getByRole('button', { name: /分页证据 20/ })).toBeVisible();
  await expect(inspector.getByText('尾页新增证据')).toHaveCount(0);
  await expect(page.getByText('21 条', { exact: true })).toBeVisible();
  await inspector.getByRole('button', { name: '加载更多证据' }).click();
  await expect(inspector.getByRole('button', { name: /尾页新增证据/ })).toBeVisible();
  await expect(inspector).toContainText('已显示 21 / 21 条');
  await expect(inspector.getByRole('button', { name: '加载更多证据' })).toHaveCount(0);
});

test('证据分页失败时只标记快照范围，重试后恢复服务端总数', async ({ page }) => {
  let allowSuccess = false;
  await page.route('**/api/v1/incidents/IN-WORKBENCH/evidence?**', (route) => {
    if (!allowSuccess) return route.fulfill({ status: 503, json: {
      error: { code: 'EVIDENCE_UNAVAILABLE', message: '暂时不可用', trace_id: 'TRACE-PAGE-1' },
    } });
    return route.fulfill({ json: {
      items: incident.evidence.map((item) => ({ ...item, incident_id: incident.incident_id })),
      total: 2, page: 1, page_size: 20,
    } });
  });
  await page.setViewportSize({ width: 1920, height: 1000 });
  await page.goto('/incidents/IN-WORKBENCH');
  await page.getByRole('button', { name: '打开证据概览，共 2 条' }).click();
  const inspector = page.getByRole('dialog', { name: '证据检查器' }).getByRole('region', { name: '证据检查器' });
  await expect(inspector.getByRole('alert')).toContainText('仅显示当前案件快照');
  await expect(inspector.getByRole('alert')).toContainText('TRACE-PAGE-1');
  await expect(page.getByText('当前快照 2 条（总数未核实）')).toBeVisible();
  allowSuccess = true;
  await inspector.getByRole('button', { name: '重试证据分页' }).click();
  await expect(inspector).toContainText('已显示 2 / 2 条');
  await expect(inspector.getByRole('alert')).toHaveCount(0);
});

test('宽屏图谱选中步骤后只列出它引用的真实证据，并显示授权原文与 PostgreSQL 校验', async ({ page }) => {
  let sessionEnabled = false;
  const session = { actor_id: 'demo-reviewer', role: 'reviewer', allowed_actions: ['approve', 'reject'], expires_at: '2030-01-01T00:00:00Z' };
  await page.route('**/api/v1/session', (route) => route.fulfill(sessionEnabled
    ? { json: session } : { status: 401, json: { error: { code: 'SESSION_REQUIRED', message: 'login required', trace_id: null } } }));
  await page.route('**/api/v1/session/demo', (route) => {
    sessionEnabled = true;
    return route.fulfill({ json: session });
  });
  await page.route('**/api/v1/incidents/IN-WORKBENCH/evidence/EV-01K5TESTTESTTESTTESTTESTTESU', (route) => route.fulfill({ json: evidenceDetail }));
  await page.setViewportSize({ width: 1920, height: 1000 });
  await page.goto('/incidents/IN-WORKBENCH');
  await expect(page.getByRole('region', { name: '攻击链' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '证据检查器' })).toHaveCount(0);
  const columns = await page.getByTestId('workbench-grid').evaluate((element) => getComputedStyle(element).gridTemplateColumns.split(' ').map(Number.parseFloat));
  expect(columns).toHaveLength(2);
  expect(columns[1] / columns[0]).toBeGreaterThan(3);
  await expect(page.getByRole('button', { name: /第 2 步.*可疑请求被规则捕获/ })).toBeVisible();
  await expect(page.locator('.react-flow__edge')).toHaveCount(0);
  await page.getByRole('button', { name: /第 2 步.*可疑请求被规则捕获/ }).click();
  const evidenceDrawer = page.getByRole('dialog', { name: '证据检查器' });
  await expect(evidenceDrawer).toBeVisible();
  const inspector = evidenceDrawer.getByRole('region', { name: '证据检查器' });
  await expect(inspector.getByText('规则命中记录')).toBeVisible();
  await expect(inspector.getByText('入口请求日志')).toHaveCount(0);
  await inspector.getByRole('button', { name: /规则命中记录/ }).click();
  await expect(inspector.getByText('"request_path": "/login"')).toHaveCount(0);
  await inspector.getByRole('button', { name: '启用本地演示账户' }).click();
  await expect(inspector.getByText('EV-01K5TESTTESTTESTTESTTESTTESU', { exact: true })).toBeVisible();
  await expect(inspector.getByText('b'.repeat(64), { exact: true }).first()).toBeVisible();
  await expect(inspector.getByText('"event_id": "EVT-2"')).toBeVisible();
  await expect(inspector.getByText('"request_path": "/login"')).toBeVisible();
  await expect(inspector).toContainText('PostgreSQL');
  await expect(inspector).toContainText('本次校验通过');
  await expect(page.getByRole('region', { name: '攻击链' })).toContainText('关系未知');
});

test('一致性快照提供关系边时仅绘制后端关系并展示节点支持状态', async ({ page }) => {
  await page.route('**/api/v1/investigations/IV-WORKBENCH', (route) => route.fulfill({ json: snapshotWithEdge('temporal') }));
  await page.setViewportSize({ width: 1920, height: 1000 });
  await page.goto('/incidents/IN-WORKBENCH');
  await expect(page.locator('.react-flow__edge')).toHaveCount(1);
  await expect(page.locator('.react-flow__edge')).toContainText('时间先后');
  await expect(page.locator('.react-flow__edge-path')).toHaveAttribute('marker-end', /arrowclosed/);
  await expect(page.getByRole('region', { name: '攻击链' })).toContainText('证据引用完整');
  await expect(page.getByRole('region', { name: '攻击链' })).toContainText('后端关系');
});

test('攻击节点和阶段列表展示步骤自己的实体时间与置信度，选中后可查看完整事实', async ({ page }) => {
  const snapshot = snapshotWithEdge('temporal');
  const enriched = {
    ...snapshot,
    attack_graph: { ...snapshot.attack_graph, nodes: snapshot.attack_graph.nodes.map((node, index) => index === 0 ? {
      ...node, host: 'step-host', service: 'step-service', confidence: 0.63, support_status: 'candidate',
    } : node) },
  };
  await page.route('**/api/v1/investigations/IV-WORKBENCH', (route) => route.fulfill({ json: enriched }));
  await page.setViewportSize({ width: 1920, height: 1000 });
  await page.goto('/incidents/IN-WORKBENCH');
  const step = page.getByRole('button', { name: /第 1 步.*外部应用访问异常/ });
  await expect(step).toContainText('step-host / step-service');
  await expect(step).toContainText('2026/09/21 18:20:24');
  await expect(step).toContainText('步骤输出置信度 63%');
  await expect(step).toContainText('候选步骤 · 待证实');
  await expect(step).toHaveAttribute('data-support-status', 'candidate');
  await step.click();
  const inspector = page.getByRole('region', { name: '证据检查器' });
  await expect(inspector).toContainText('步骤详情');
  await expect(inspector).toContainText('step-host / step-service');
  await expect(inspector).toContainText('计算依据未提供');
  await expect(inspector).not.toContainText('edge-01');
  await page.getByRole('dialog', { name: '证据检查器' }).getByRole('button', { name: '关闭' }).click();
  await page.getByRole('button', { name: '阶段列表' }).click();
  await expect(step).toContainText('step-host / step-service');
  await expect(step).toContainText('步骤输出置信度 63%');
});

test('攻击步骤缺少实体或置信度时显示未提供并保留观察时间', async ({ page }) => {
  await page.route('**/api/v1/investigations/IV-WORKBENCH', (route) => route.fulfill({ json: snapshotWithEdge('temporal') }));
  await page.setViewportSize({ width: 1920, height: 1000 });
  await page.goto('/incidents/IN-WORKBENCH');
  const step = page.getByRole('button', { name: /第 2 步.*可疑请求被规则捕获/ });
  await expect(step).toContainText('主机未提供 / 服务未提供');
  await expect(step).toContainText('置信度未提供');
  await expect(step).toContainText('2026/09/21 18:21:24');
  await expect(step).not.toContainText('80%');
  await page.getByRole('button', { name: '阶段列表' }).click();
  await expect(step).toContainText('主机未提供 / 服务未提供');
  await expect(step).toContainText('置信度未提供');
});

test('因果候选保持虚线箭头和待证实语义', async ({ page }) => {
  await page.route('**/api/v1/investigations/IV-WORKBENCH', (route) => route.fulfill({
    json: snapshotWithEdge('causal_candidate', 'candidate'),
  }));
  await page.goto('/incidents/IN-WORKBENCH');
  const edge = page.locator('.react-flow__edge');
  await expect(edge).toHaveCount(1);
  await expect(edge).toContainText('因果候选');
  await expect(edge).toContainText('待证实');
  await expect(edge).toHaveAttribute('aria-label', /可能导致.*待证实/);
  await expect(edge.locator('.react-flow__edge-path')).toHaveAttribute('marker-end', /arrowclosed/);
  expect(await edge.locator('.react-flow__edge-path').evaluate((element) => (element as SVGPathElement).style.strokeDasharray)).toBe('6, 4');
});

test('行为关联是无方向点线，不伪称上一步导致下一步', async ({ page }) => {
  await page.route('**/api/v1/investigations/IV-WORKBENCH', (route) => route.fulfill({
    json: snapshotWithEdge('related'),
  }));
  await page.goto('/incidents/IN-WORKBENCH');
  const edge = page.locator('.react-flow__edge');
  await expect(edge).toHaveCount(1);
  await expect(edge).toContainText('行为关联');
  await expect(edge).toHaveAttribute('aria-label', /方向未定义/);
  await expect(edge.locator('.react-flow__edge-path')).not.toHaveAttribute('marker-end', /./);
  expect(await edge.locator('.react-flow__edge-path').evaluate((element) => (element as SVGPathElement).style.strokeDasharray)).toBe('2, 4');
});

test('证据详情缺失或无权访问时保留引用和步骤，可重试且不显示校验通过', async ({ page }) => {
  await page.route('**/api/v1/incidents/IN-WORKBENCH/evidence/EV-01K5TESTTESTTESTTESTTESTTESU', (route) => route.fulfill({
    status: 404, json: { error: { code: 'NOT_FOUND', message: 'evidence not found', trace_id: 'TRACE-evidence-404' } },
  }));
  await page.goto('/incidents/IN-WORKBENCH');
  await page.getByRole('button', { name: '阶段列表' }).click();
  await page.getByRole('button', { name: /第 2 步.*可疑请求被规则捕获/ }).click();
  const inspector = page.getByRole('region', { name: '证据检查器' });
  await inspector.getByRole('button', { name: /规则命中记录/ }).click();
  await expect(inspector).toContainText('不存在或无权访问');
  await expect(inspector).toContainText('TRACE-evidence-404');
  await expect(inspector.getByRole('button', { name: /规则命中记录/ })).toBeVisible();
  await expect(page.getByRole('button', { name: /第 2 步.*可疑请求被规则捕获/ })).toHaveAttribute('aria-pressed', 'true');
  await expect(inspector).not.toContainText('本次校验通过');
});

test('证据哈希不匹配时明确标记异常，不当作通过', async ({ page }) => {
  await page.route('**/api/v1/incidents/IN-WORKBENCH/evidence/EV-01K5TESTTESTTESTTESTTESTTESU', (route) => route.fulfill({
    json: { ...evidenceDetail, integrity: { ...evidenceDetail.integrity, status: 'mismatch', calculated_sha256: 'c'.repeat(64) } },
  }));
  await page.goto('/incidents/IN-WORKBENCH');
  await page.getByRole('button', { name: '阶段列表' }).click();
  await page.getByRole('button', { name: /第 2 步.*可疑请求被规则捕获/ }).click();
  const inspector = page.getByRole('region', { name: '证据检查器' });
  await inspector.getByRole('button', { name: /规则命中记录/ }).click();
  await expect(inspector.getByRole('alert')).toContainText('哈希不匹配');
  await expect(inspector).not.toContainText('本次校验通过');
});

test('服务端无法计算哈希时显示不可用，不伪造一致结论', async ({ page }) => {
  await page.route('**/api/v1/incidents/IN-WORKBENCH/evidence/EV-01K5TESTTESTTESTTESTTESTTESU', (route) => route.fulfill({
    json: { ...evidenceDetail, integrity: { ...evidenceDetail.integrity, status: 'unavailable', calculated_sha256: null } },
  }));
  await page.goto('/incidents/IN-WORKBENCH');
  await page.getByRole('button', { name: '阶段列表' }).click();
  await page.getByRole('button', { name: /第 2 步.*可疑请求被规则捕获/ }).click();
  const inspector = page.getByRole('region', { name: '证据检查器' });
  await inspector.getByRole('button', { name: /规则命中记录/ }).click();
  await expect(inspector.getByRole('alert')).toContainText('校验不可用');
  await expect(inspector).not.toContainText('本次校验通过');
});

test('阶段证据与六角色运行记录分别使用侧边抽屉且只展示真实字段', async ({ page }) => {
  await page.goto('/incidents/IN-WORKBENCH');
  await page.getByRole('button', { name: '阶段列表' }).click();
  await page.getByRole('button', { name: /第 2 步.*可疑请求被规则捕获/ }).click();
  const evidenceDrawer = page.getByRole('dialog', { name: '证据检查器' });
  await expect(evidenceDrawer.getByRole('region', { name: '证据检查器' })).toContainText('规则命中记录');
  await evidenceDrawer.getByRole('button', { name: '关闭' }).click();

  const progress = page.getByRole('region', { name: '六角色进度' });
  await expect(progress).toContainText('分诊');
  await expect(progress).toContainText('证据收集');
  await expect(progress).toContainText('等待批准后执行');
  await expect(progress).not.toContainText('RUN-1');
  await expect(progress).not.toContainText('RUN-2');

  await progress.getByRole('button', { name: '查看分诊运行记录（1）' }).click();
  const runDrawer = page.getByRole('dialog', { name: '运行记录' });
  await expect(runDrawer.getByRole('region', { name: '分诊运行记录' })).toContainText('RUN-1');
  await expect(runDrawer).toContainText('2026/09/21 18:20:24');
  await expect(runDrawer).not.toContainText('RUN-2');
  await runDrawer.getByRole('button', { name: '关闭' }).click();

  await progress.getByRole('button', { name: '查看证据收集运行记录（1）' }).click();
  await expect(runDrawer.getByRole('region', { name: '证据收集运行记录' })).toContainText('RUN-2');
  await expect(runDrawer).toContainText('EV-01K5TESTTESTTESTTESTTESTTESU');
  await expect(runDrawer).not.toContainText('RUN-3');
});

test('窄屏点击阶段步骤从右侧打开证据抽屉，关闭后仍保持选中步骤', async ({ page }) => {
  await page.setViewportSize({ width: 760, height: 900 });
  await page.goto('/incidents/IN-WORKBENCH');
  const columns = await page.getByTestId('workbench-grid').evaluate((element) => getComputedStyle(element).gridTemplateColumns.split(' ').map(Number.parseFloat));
  expect(columns).toHaveLength(1);
  await page.getByRole('button', { name: /第 2 步.*可疑请求被规则捕获/ }).click();
  const drawer = page.getByRole('dialog', { name: '证据检查器' });
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText('规则命中记录');
  await drawer.getByRole('button', { name: '关闭' }).click();
  await expect(drawer).toBeHidden();
  await expect(page.getByRole('button', { name: /第 2 步.*可疑请求被规则捕获/ })).toHaveAttribute('aria-pressed', 'true');

  const runTrigger = page.getByRole('button', { name: '查看分诊运行记录（1）' });
  await runTrigger.click();
  const runDrawer = page.getByRole('dialog', { name: '运行记录' });
  await expect(runDrawer).toContainText('RUN-1');
  await runDrawer.getByRole('button', { name: '关闭' }).click();
  await expect(runDrawer).toBeHidden();
  await expect(runTrigger).toBeFocused();
});
