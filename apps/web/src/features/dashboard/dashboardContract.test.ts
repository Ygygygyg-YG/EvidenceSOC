import { afterEach, expect, it, vi } from 'vitest';
import { dashboardAlertHref, dashboardIncidentHref, dashboardSchema, loadSourceHealth, readDashboardWindow, sourceHealthSchema } from './dashboardContract';

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

const sample = {
  window: '24h', execution_mode: 'rules', time_from: '2026-09-30T00:00:00Z', time_to: '2026-10-01T00:00:00Z',
  generated_at: '2026-10-01T00:00:00Z',
  metrics: { alerts_in_window: 1, high_risk_incidents: 1, running_investigations: 0, pending_response_plans: 1 },
  alert_trend: [{ bucket_start: '2026-09-30T00:00:00Z', bucket_end: '2026-09-30T01:00:00Z', total: 1, high_risk: 1 }],
  incident_status_distribution: [{ status: 'awaiting_approval', count: 1 }],
  recent_alerts: [{ alert_id: 'AL-1', title: 'SQL 注入告警', severity: 'high', created_at: '2026-09-30T00:30:00Z', event_ids: ['SE-1'], status: 'awaiting_approval' }],
  recent_activity: [{ event: 'approval.required', occurred_at: '2026-09-30T00:40:00Z', incident_id: 'IN-1', investigation_id: 'IV-1' }],
  source_health: { checked_at: '2026-10-01T00:00:00Z', postgresql_status: 'ok', opensearch_status: null,
    is_stale: false, sources: [{ source: 'nginx', last_ingested_at: '2026-09-30T00:20:00Z',
      ingestion_lag_seconds: 85200, status: null, is_stale: null }] },
} as const;

it('解析真实聚合数据，保留未知健康状态和真实零', () => {
  const parsed = dashboardSchema.parse(sample);
  expect(parsed.metrics.running_investigations).toBe(0);
  expect(parsed.source_health.opensearch_status).toBeNull();
  expect(dashboardSchema.safeParse({ ...sample, metrics: { ...sample.metrics, alerts_in_window: -1 } }).success).toBe(false);
  expect(dashboardSchema.safeParse({ ...sample, alert_trend: [{ ...sample.alert_trend[0], high_risk: 2 }] }).success).toBe(false);
});

it('只接受已定义的时间窗口', () => {
  expect(readDashboardWindow(new URLSearchParams('window=1h'))).toBe('1h');
  expect(readDashboardWindow(new URLSearchParams('window=7d'))).toBe('7d');
  expect(readDashboardWindow(new URLSearchParams('window=bad'))).toBe('24h');
});

it('下钻告警使用服务端实际窗口，不从 7d 重新推算时间', () => {
  expect(dashboardAlertHref(sample)).toBe('/alerts?page=1&page_size=20&time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
  expect(dashboardAlertHref(sample, sample.alert_trend[0])).toBe('/alerts?page=1&page_size=20&time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-09-30T01%3A00%3A00Z');
});

it('高危调查和状态分布下钻使用服务端实际窗口并匹配指标口径', () => {
  expect(dashboardIncidentHref(sample, { risk: 'high' })).toBe('/incidents?page=1&page_size=20&risk=high&time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
  expect(dashboardIncidentHref(sample, { status: 'awaiting_approval' })).toBe('/incidents?page=1&page_size=20&status=awaiting_approval&time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z');
});

it('数据源健康单独读取并保留未知状态，不推断健康', async () => {
  const health = sourceHealthSchema.parse(sample.source_health);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(health), { status: 200 })));
  const actual = await loadSourceHealth();
  expect(actual).toEqual(health);
  expect(actual.sources[0].status).toBeNull();
  expect(actual.sources[0].ingestion_lag_seconds).toBe(85200);
  expect(sourceHealthSchema.safeParse({ ...health, sources: [{ ...health.sources[0], ingestion_lag_seconds: -1 }] }).success).toBe(false);
});
