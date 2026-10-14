import { z } from 'zod';
import type { components } from '@/lib/api/generated';
import { buildAlertsQuery, severityValues, statusValues } from '../alerts/alertsContract';
import { buildIncidentsQuery, type IncidentFilters } from '../incidents/incidentsListContract';

export const dashboardWindows = ['1h', '24h', '7d'] as const;
export type DashboardWindow = typeof dashboardWindows[number];
const dateTime = z.iso.datetime({ offset: true });
const nonnegative = z.number().int().nonnegative();

export const sourceHealthSchema = z.object({
  checked_at: dateTime,
  postgresql_status: z.enum(['ok', 'degraded', 'failed']).nullable(),
  opensearch_status: z.enum(['ok', 'degraded', 'failed']).nullable(),
  is_stale: z.boolean().nullable(),
  sources: z.array(z.object({
    source: z.string().min(1), last_ingested_at: dateTime,
    ingestion_lag_seconds: nonnegative.nullable(),
    status: z.enum(['ok', 'degraded', 'failed']).nullable(),
    is_stale: z.boolean().nullable(),
  })),
});
export type SourceHealthData = z.infer<typeof sourceHealthSchema>;

export const dashboardSchema = z.object({
  window: z.enum(dashboardWindows), execution_mode: z.enum(['rules', 'model']),
  time_from: dateTime, time_to: dateTime, generated_at: dateTime,
  metrics: z.object({
    alerts_in_window: nonnegative, high_risk_incidents: nonnegative,
    running_investigations: nonnegative, pending_response_plans: nonnegative,
  }),
  alert_trend: z.array(z.object({
    bucket_start: dateTime, bucket_end: dateTime, total: nonnegative, high_risk: nonnegative,
  })),
  incident_status_distribution: z.array(z.object({ status: z.enum(statusValues), count: nonnegative })),
  recent_alerts: z.array(z.object({
    alert_id: z.string().min(1), title: z.string().min(1), severity: z.enum(severityValues),
    created_at: dateTime, event_ids: z.array(z.string().min(1)).min(1), status: z.enum(statusValues),
  })),
  recent_activity: z.array(z.object({
    event: z.string().min(1), occurred_at: dateTime,
    incident_id: z.string().min(1), investigation_id: z.string().min(1),
  })),
  source_health: sourceHealthSchema,
}).superRefine((data, context) => {
  if (Date.parse(data.time_from) >= Date.parse(data.time_to)) {
    context.addIssue({ code: 'custom', message: '统计时间区间无效。' });
  }
  if (data.alert_trend.some((bucket) => bucket.high_risk > bucket.total
    || Date.parse(bucket.bucket_start) >= Date.parse(bucket.bucket_end))) {
    context.addIssue({ code: 'custom', message: '告警趋势数据无效。' });
  }
}) satisfies z.ZodType<components['schemas']['DashboardSummary']>;

export type DashboardData = z.infer<typeof dashboardSchema>;

export function dashboardAlertHref(data: Pick<DashboardData, 'time_from' | 'time_to'>,
  bucket?: Pick<DashboardData['alert_trend'][number], 'bucket_start' | 'bucket_end'>): string {
  return `/alerts?${buildAlertsQuery({ page: 1, pageSize: 20,
    timeFrom: bucket?.bucket_start ?? data.time_from, timeTo: bucket?.bucket_end ?? data.time_to })}`;
}

export function dashboardIncidentHref(data: Pick<DashboardData, 'time_from' | 'time_to'>,
  filters: Pick<IncidentFilters, 'status' | 'risk'> = {}): string {
  return `/incidents?${buildIncidentsQuery({ page: 1, pageSize: 20,
    ...filters, timeFrom: data.time_from, timeTo: data.time_to })}`;
}

export function readDashboardWindow(params: Pick<URLSearchParams, 'get'>): DashboardWindow {
  const raw = params.get('window');
  return dashboardWindows.find((value) => value === raw) ?? '24h';
}

export class DashboardRequestError extends Error {
  constructor(public code: string, message: string, public traceId?: string, public status?: number) {
    super(message);
    this.name = 'DashboardRequestError';
  }
}

const errorEnvelope = z.object({ error: z.object({
  code: z.string(), message: z.string(), trace_id: z.string().nullable(),
}) });

export async function loadDashboard(window: DashboardWindow, signal?: AbortSignal): Promise<DashboardData> {
  let response: Response;
  try {
    response = await fetch(`/api/v1/dashboard/summary?window=${window}`, {
      signal, cache: 'no-store', headers: { Accept: 'application/json' },
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new DashboardRequestError('NETWORK_ERROR', '无法连接统计服务，请重试。');
  }
  const trace = response.headers.get('x-trace-id') || undefined;
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new DashboardRequestError('INVALID_RESPONSE', '统计服务返回了无法读取的数据。', trace, response.status); }
  if (!response.ok) {
    const parsed = errorEnvelope.safeParse(body);
    if (parsed.success) throw new DashboardRequestError(parsed.data.error.code, parsed.data.error.message,
      parsed.data.error.trace_id || trace, response.status);
    throw new DashboardRequestError('HTTP_ERROR', `统计请求失败（HTTP ${response.status}）。`, trace, response.status);
  }
  const parsed = dashboardSchema.safeParse(body);
  if (!parsed.success || parsed.data.window !== window) {
    throw new DashboardRequestError('INVALID_RESPONSE', '统计数据不符合接口契约。', trace, response.status);
  }
  return parsed.data;
}

export async function loadSourceHealth(signal?: AbortSignal): Promise<SourceHealthData> {
  let response: Response;
  try {
    response = await fetch('/api/v1/data-sources/health', {
      signal, cache: 'no-store', headers: { Accept: 'application/json' },
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new DashboardRequestError('NETWORK_ERROR', '无法连接数据源健康服务，请重试。');
  }
  const trace = response.headers.get('x-trace-id') || undefined;
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new DashboardRequestError('INVALID_RESPONSE', '数据源健康服务返回了无法读取的数据。', trace, response.status); }
  if (!response.ok) {
    const parsed = errorEnvelope.safeParse(body);
    if (parsed.success) throw new DashboardRequestError(parsed.data.error.code, parsed.data.error.message,
      parsed.data.error.trace_id || trace, response.status);
    throw new DashboardRequestError('HTTP_ERROR', `健康请求失败（HTTP ${response.status}）。`, trace, response.status);
  }
  const parsed = sourceHealthSchema.safeParse(body);
  if (!parsed.success) {
    throw new DashboardRequestError('INVALID_RESPONSE', '数据源健康数据不符合接口契约。', trace, response.status);
  }
  return parsed.data;
}
