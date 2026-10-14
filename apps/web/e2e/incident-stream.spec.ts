import { expect, test } from '@playwright/test';
import type { components } from '../src/lib/api/generated';

type IncidentDetail = components['schemas']['IncidentDetail'];

const initial: IncidentDetail = {
  incident_id: 'IN-STREAM', alert_id: 'AL-STREAM', status: 'collecting',
  created_at: '2026-09-21T10:20:24Z', investigation_id: 'IV-STREAM', trace_id: 'TRACE-STREAM',
  alerts: [{ alert_id: 'AL-STREAM', title: '事件流演示告警', severity: 'high',
    created_at: '2026-09-21T10:20:24Z', event_ids: ['EVENT-STREAM'] }],
  evidence: [], knowledge: [], attack_steps: [], runs: [], origin: null, classification: null,
  response_plan: null, approval: null, validation_result: null, simulation: [], fallback_used: false,
  errors: [], stop_reason: null,
};

function streamSnapshot(phase: number, cursor: string, status = 'collecting') {
  return {
    ...initial, status, revision: String(phase + 1), stream_cursor: cursor,
    updated_at: '2026-09-21T10:20:25Z', mode: 'rules', available_actions: [],
    attack_graph: { revision: String(phase + 1), generated_at: '2026-09-21T10:20:25Z', nodes: [], edges: [] },
  };
}

async function installControllableEventSource(page: import('@playwright/test').Page) {
  await page.addInitScript(() => {
    class MockEventSource {
      onopen: ((event: Event) => void) | null = null;
      onerror: ((event: Event) => void) | null = null;
      closed = false;
      listeners = new Map<string, Array<(event: MessageEvent) => void>>();
      constructor(public url: string) {
        (window as unknown as Window & { __mockStreams: MockEventSource[] }).__mockStreams.push(this);
        queueMicrotask(() => this.onopen?.(new Event('open')));
      }
      addEventListener(name: string, listener: (event: MessageEvent) => void) {
        this.listeners.set(name, [...(this.listeners.get(name) ?? []), listener]);
      }
      emit(name: string, id = '', data: Record<string, unknown> = {}) {
        if (this.closed) return;
        for (const listener of this.listeners.get(name) ?? []) {
          listener(new MessageEvent(name, { lastEventId: id, data: JSON.stringify(data) }));
        }
      }
      fail() { this.onerror?.(new Event('error')); }
      close() { this.closed = true; }
    }
    (window as unknown as Window & { __mockStreams: MockEventSource[] }).__mockStreams = [];
    window.EventSource = MockEventSource as unknown as typeof EventSource;
  });
}

async function mockStreamCount(page: import('@playwright/test').Page) {
  return page.evaluate(() => (window as unknown as Window & { __mockStreams: unknown[] }).__mockStreams.length);
}

async function mockStreamCursors(page: import('@playwright/test').Page) {
  return page.evaluate(() => (window as unknown as Window & { __mockStreams: Array<{ url: string }> }).__mockStreams
    .map((stream) => new URL(stream.url, location.origin).searchParams.get('cursor')));
}

async function emitMockEvent(page: import('@playwright/test').Page, index: number, name: string, id = '',
  data: Record<string, unknown> = {}) {
  await page.evaluate(({ index, name, id, data }) => {
    (window as unknown as Window & { __mockStreams: Array<{ emit: (name: string, id: string, data: Record<string, unknown>) => void }> })
      .__mockStreams[index].emit(name, id, data);
  }, { index, name, id, data });
}

test('事件序号出现缺口时关闭旧流、重读快照并从新游标订阅', async ({ page }) => {
  let phase = 0;
  let snapshotReads = 0;
  await installControllableEventSource(page);
  await page.route('**/api/v1/incidents/IN-STREAM', (route) => route.fulfill({ json: initial }));
  await page.route('**/api/v1/investigations/IV-STREAM', (route) => {
    snapshotReads += 1;
    return route.fulfill({ json: streamSnapshot(phase, phase ? '2' : '0') });
  });
  await page.goto('/incidents/IN-STREAM');
  await expect.poll(() => mockStreamCount(page)).toBe(1);

  phase = 1;
  await emitMockEvent(page, 0, 'agent.started', '2', { investigation_id: 'IV-STREAM' });
  await expect.poll(() => mockStreamCount(page)).toBe(2);
  expect(await mockStreamCursors(page)).toEqual(['0', '2']);
  expect(snapshotReads).toBeGreaterThanOrEqual(2);
  expect(await page.evaluate(() => (window as unknown as Window & { __mockStreams: Array<{ closed: boolean }> }).__mockStreams[0].closed)).toBe(true);
});

test('服务端 reset 后丢弃旧游标并从最新快照续订', async ({ page }) => {
  let cursor = '0';
  await installControllableEventSource(page);
  await page.route('**/api/v1/incidents/IN-STREAM', (route) => route.fulfill({ json: initial }));
  await page.route('**/api/v1/investigations/IV-STREAM', (route) => route.fulfill({ json: streamSnapshot(1, cursor) }));
  await page.goto('/incidents/IN-STREAM');
  await expect.poll(() => mockStreamCount(page)).toBe(1);

  cursor = '5';
  await emitMockEvent(page, 0, 'stream.reset', '', {
    schema_version: 1, investigation_id: 'IV-STREAM', occurred_at: '2026-09-21T10:20:25Z',
    reason: 'CURSOR_EXPIRED',
  });
  await expect.poll(() => mockStreamCount(page)).toBe(2);
  expect(await mockStreamCursors(page)).toEqual(['0', '5']);
  expect(await page.evaluate(() => (window as unknown as Window & { __mockStreams: Array<{ closed: boolean }> }).__mockStreams[0].closed)).toBe(true);
});

for (const status of [401, 403]) {
  test(`快照校准返回 ${status} 后停止当前订阅`, async ({ page }) => {
    let denied = false;
    await installControllableEventSource(page);
    await page.route('**/api/v1/incidents/IN-STREAM', (route) => route.fulfill({ json: initial }));
    await page.route('**/api/v1/investigations/IV-STREAM', (route) => denied
      ? route.fulfill({ status, json: { error: { code: status === 401 ? 'UNAUTHORIZED' : 'FORBIDDEN',
        message: 'Access denied', trace_id: 'TRACE-denied' } } })
      : route.fulfill({ json: streamSnapshot(0, '0') }));
    await page.goto('/incidents/IN-STREAM');
    await expect.poll(() => mockStreamCount(page)).toBe(1);

    denied = true;
    await page.evaluate(() => {
      (window as unknown as Window & { __mockStreams: Array<{ fail: () => void }> }).__mockStreams[0].fail();
    });
    await expect(page.getByRole('alert').filter({ hasText: status === 401 ? '会话已失效' : '无权查看' })).toBeVisible();
    expect(await page.evaluate(() => (window as unknown as Window & { __mockStreams: Array<{ closed: boolean }> }).__mockStreams[0].closed)).toBe(true);
    expect(await mockStreamCount(page)).toBe(1);
  });
}

test('业务心跳重置活动计时，随后失联超过 30 秒才校准重连', async ({ page }) => {
  await page.clock.install();
  await installControllableEventSource(page);
  await page.route('**/api/v1/incidents/IN-STREAM', (route) => route.fulfill({ json: initial }));
  await page.route('**/api/v1/investigations/IV-STREAM', (route) => route.fulfill({ json: streamSnapshot(0, '0') }));
  await page.goto('/incidents/IN-STREAM');
  await expect.poll(() => mockStreamCount(page)).toBe(1);

  await page.clock.fastForward(20_000);
  await emitMockEvent(page, 0, 'stream.heartbeat', '', {
    schema_version: 1, investigation_id: 'IV-STREAM', occurred_at: '2026-09-21T10:20:25Z',
  });
  await page.clock.fastForward(20_000);
  expect(await mockStreamCount(page)).toBe(1);
  await page.clock.fastForward(10_100);
  await expect.poll(() => mockStreamCount(page)).toBe(2);
  expect(await mockStreamCursors(page)).toEqual(['0', '0']);
});

test('客户端切换调查时关闭旧流，迟到事件不改写新案件', async ({ page }) => {
  const other = {
    ...initial, incident_id: 'IN-OTHER', investigation_id: 'IV-OTHER', alert_id: 'AL-OTHER',
    alerts: [{ ...initial.alerts[0], alert_id: 'AL-OTHER', title: '另一调查告警' }],
  };
  await installControllableEventSource(page);
  await page.route('**/api/v1/incidents/IN-STREAM', (route) => route.fulfill({ json: initial }));
  await page.route('**/api/v1/incidents/IN-OTHER', (route) => route.fulfill({ json: other }));
  await page.route('**/api/v1/incidents?**', (route) => route.fulfill({ json: {
    items: [{ incident_id: 'IN-OTHER', investigation_id: 'IV-OTHER', alert_id: 'AL-OTHER',
      alert_title: '另一调查告警', severity: 'high', status: 'collecting',
      created_at: initial.created_at, evidence_count: 0, validation_outcome: null }],
    total: 1, page: 1, page_size: 20,
  } }));
  await page.route('**/api/v1/investigations/IV-STREAM', (route) => route.fulfill({ json: streamSnapshot(0, '0') }));
  await page.route('**/api/v1/investigations/IV-OTHER', (route) => route.fulfill({ json: {
    ...streamSnapshot(0, '0'), ...other,
  } }));
  await page.goto('/incidents/IN-STREAM');
  await expect.poll(() => mockStreamCount(page)).toBe(1);

  await page.getByRole('navigation', { name: '主导航' }).getByRole('link', { name: '调查列表' }).click();
  await page.getByRole('table', { name: '案件记录' }).getByRole('link', { name: 'IN-OTHER' }).click();
  await expect(page.getByRole('region', { name: '调查上下文' }).getByRole('link', { name: '另一调查告警' })).toBeVisible();
  await expect.poll(() => mockStreamCount(page)).toBe(2);
  expect(await page.evaluate(() => (window as unknown as Window & { __mockStreams: Array<{ closed: boolean }> }).__mockStreams[0].closed)).toBe(true);
  await emitMockEvent(page, 0, 'evidence.added', '1', { investigation_id: 'IV-STREAM' });
  expect(await mockStreamCursors(page)).toEqual(['0', '0']);
  await expect(page.getByRole('region', { name: '调查上下文' }).getByRole('link', { name: '另一调查告警' })).toBeVisible();
});

test('事件到达后刷新案件快照，断线重放时不重复证据', async ({ page }) => {
  let phase = 0;
  let connections = 0;
  let snapshotReads = 0;
  const cursors: string[] = [];
  await page.route('**/api/v1/incidents/IN-STREAM', (route) => route.fulfill({ json: initial }));
  await page.route('**/api/v1/investigations/IV-STREAM', (route) => {
    snapshotReads += 1;
    return route.fulfill({ json: {
    ...initial, status: phase === 2 ? 'completed' : 'collecting',
    evidence: phase ? [{ evidence_id: 'EV-01K5TESTTESTTESTTESTTESTTEST', event_id: 'EVENT-STREAM',
      source: 'nginx', observed_at: '2026-09-21T10:20:24Z', query: { event_id: 'EVENT-STREAM' },
      summary: '重连后仍只有一条证据', content_sha256: 'a'.repeat(64) }] : [],
    revision: String(phase + 1), stream_cursor: String(phase),
    updated_at: '2026-09-21T10:20:25Z', mode: 'rules', available_actions: [],
    attack_graph: { revision: String(phase + 1), generated_at: '2026-09-21T10:20:25Z', nodes: [], edges: [] },
  } });
  });
  await page.route('**/api/v1/investigations/IV-STREAM/stream*', async (route) => {
    connections += 1;
    cursors.push(new URL(route.request().url()).searchParams.get('cursor') ?? '');
    if (connections === 1) {
      phase = 1;
      await route.fulfill({ contentType: 'text/event-stream', body: 'id: 1\nevent: evidence.added\ndata: {"investigation_id":"IV-STREAM"}\n\n' });
    } else {
      phase = 2;
      await route.fulfill({ contentType: 'text/event-stream', body: 'id: 1\nevent: evidence.added\ndata: {"investigation_id":"IV-STREAM"}\n\nid: 2\nevent: investigation.completed\ndata: {"investigation_id":"IV-STREAM"}\n\n' });
    }
  });
  await page.goto('/incidents/IN-STREAM');
  await expect(page.getByText('重连后仍只有一条证据')).toBeVisible();
  await expect.poll(() => connections).toBeGreaterThanOrEqual(2);
  expect(cursors[0]).toBe('0');
  expect(cursors[1]).toBe('0');
  expect(snapshotReads).toBeGreaterThanOrEqual(2);
  await expect(page.getByRole('button', { name: /重连后仍只有一条证据/ })).toHaveCount(1);
  await expect(page.getByText('已完成')).toBeVisible();
  await page.waitForTimeout(1250);
  expect(connections).toBe(2);
});

test('刷新后以终态快照覆盖旧案件状态，不再订阅事件流', async ({ page }) => {
  let connections = 0;
  await page.route('**/api/v1/incidents/IN-STREAM', (route) => route.fulfill({ json: initial }));
  await page.route('**/api/v1/investigations/IV-STREAM', (route) => route.fulfill({ json: {
    ...initial, status: 'completed', revision: '5', stream_cursor: '4',
    updated_at: '2026-09-21T10:25:00Z', mode: 'rules', available_actions: [],
    attack_graph: { revision: '5', generated_at: '2026-09-21T10:25:00Z', nodes: [], edges: [] },
  } }));
  await page.route('**/api/v1/investigations/IV-STREAM/stream*', (route) => {
    connections += 1;
    return route.fulfill({ contentType: 'text/event-stream', body: '' });
  });
  await page.goto('/incidents/IN-STREAM');
  await expect(page.getByText('已完成', { exact: true }).first()).toBeVisible();
  expect(connections).toBe(0);
});
