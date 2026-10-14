import { z } from 'zod';
import type { components } from '../../lib/api/generated';

export type AlertPage = components['schemas']['AlertPage'];
export type AlertListItem = components['schemas']['AlertListItem'];
export type Severity = components['schemas']['Severity'];
export type IncidentStatus = components['schemas']['IncidentStatus'];

export const severityValues = ['info', 'low', 'medium', 'high', 'critical'] as const satisfies readonly Severity[];
export const statusValues = [
  'received', 'triaged', 'collecting', 'analyzing', 'reconstructing', 'awaiting_approval',
  'simulating', 'validating', 'completed', 'failed', 'manual_review', 'rejected',
] as const satisfies readonly IncidentStatus[];
export const pageSizeOptions = [20, 50, 100] as const;
export const severityLabels: Record<Severity, string> = { info: '信息', low: '低危', medium: '中危', high: '高危', critical: '严重' };
export const statusLabels: Record<IncidentStatus, string> = {
  received: '已接收', triaged: '已分诊', collecting: '收集中', analyzing: '分析中',
  reconstructing: '重构中', awaiting_approval: '待审批', simulating: '模拟中', validating: '验证中',
  completed: '已完成', failed: '失败', manual_review: '待复核', rejected: '已拒绝',
};

const alertItemSchema = z.object({
  alert_id: z.string().min(1), title: z.string().min(1), severity: z.enum(severityValues),
  created_at: z.iso.datetime({ offset: true }), event_ids: z.array(z.string().min(1)).min(1), status: z.enum(statusValues),
}) satisfies z.ZodType<AlertListItem>;

export const alertPageSchema = z.object({
  items: z.array(alertItemSchema), total: z.number().int().nonnegative(),
  page: z.number().int().positive(), page_size: z.number().int().min(1).max(200),
}).superRefine((data, context) => {
  if (data.items.length > data.page_size || data.items.length > data.total) {
    context.addIssue({ code: 'custom', message: 'Invalid pagination counts.' });
  }
  if (new Set(data.items.map((item) => item.alert_id)).size !== data.items.length) {
    context.addIssue({ code: 'custom', message: 'Duplicate alert identifiers.' });
  }
}) satisfies z.ZodType<AlertPage>;

const errorEnvelopeSchema = z.object({ error: z.object({
  code: z.string(), message: z.string(), trace_id: z.string().nullable(),
}) }) satisfies z.ZodType<components['schemas']['ErrorEnvelope']>;

export type AlertFilters = { page: number; pageSize: number; severity?: Severity; status?: IncidentStatus;
  timeFrom?: string; timeTo?: string; query?: string };

export function toShanghaiDateTimeInput(value: string): string {
  return new Date(Date.parse(value) + 8 * 60 * 60 * 1000).toISOString().slice(0, 19);
}

export function fromShanghaiDateTimeInput(value: string): string | undefined {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value)) return undefined;
  const withSeconds = value.length === 16 ? `${value}:00` : value;
  const parsed = new Date(`${withSeconds}+08:00`);
  if (Number.isNaN(parsed.getTime())) return undefined;
  const iso = parsed.toISOString();
  return toShanghaiDateTimeInput(iso) === withSeconds ? iso : undefined;
}

export function resolveShanghaiDateTimeInput(value: string, original?: string): string | undefined {
  const withSeconds = value.length === 16 ? `${value}:00` : value;
  if (original && toShanghaiDateTimeInput(original) === withSeconds) return original;
  return fromShanghaiDateTimeInput(value);
}

function validTimeRange(from?: string | null, to?: string | null): from is string {
  return Boolean(from && to && z.iso.datetime({ offset: true }).safeParse(from).success
    && z.iso.datetime({ offset: true }).safeParse(to).success && Date.parse(from) < Date.parse(to));
}

export function readAlertFilters(params: Pick<URLSearchParams, 'get'>): AlertFilters {
  const page = Number(params.get('page') ?? 1);
  const pageSize = Number(params.get('page_size') ?? 20);
  const severity = params.get('severity');
  const status = params.get('status');
  const timeFrom = params.get('time_from');
  const timeTo = params.get('time_to');
  const rawQuery = params.get('query')?.trim();
  return {
    page: Number.isSafeInteger(page) && page >= 1 ? page : 1,
    pageSize: pageSizeOptions.some((value) => value === pageSize) ? pageSize : 20,
    severity: severityValues.find((value) => value === severity),
    status: statusValues.find((value) => value === status),
    timeFrom: validTimeRange(timeFrom, timeTo) ? timeFrom! : undefined,
    timeTo: validTimeRange(timeFrom, timeTo) ? timeTo! : undefined,
    query: rawQuery && rawQuery.length <= 200 ? rawQuery : undefined,
  };
}

export function buildAlertsQuery(filters: AlertFilters): string {
  const query = new URLSearchParams({ page: String(filters.page), page_size: String(filters.pageSize) });
  if (filters.severity) query.set('severity', filters.severity);
  if (filters.status) query.set('status', filters.status);
  if (validTimeRange(filters.timeFrom, filters.timeTo)) {
    query.set('time_from', filters.timeFrom!);
    query.set('time_to', filters.timeTo!);
  }
  const text = filters.query?.trim();
  if (text && text.length <= 200) query.set('query', text);
  return query.toString();
}

export function changeAlertFilters(current: AlertFilters, patch: Partial<Pick<AlertFilters, 'severity' | 'status' | 'pageSize' | 'timeFrom' | 'timeTo' | 'query'>>): AlertFilters {
  return { ...current, ...patch, query: patch.query === undefined ? current.query : patch.query.trim() || undefined, page: 1 };
}

export class AlertRequestError extends Error {
  constructor(public code: string, message: string, public traceId?: string, public status?: number) {
    super(message);
    this.name = 'AlertRequestError';
  }
}

export async function loadAlerts(filters: AlertFilters, signal?: AbortSignal): Promise<AlertPage> {
  let response: Response;
  try {
    response = await fetch(`/api/v1/alerts?${buildAlertsQuery(filters)}`, {
      signal, cache: 'no-store', headers: { Accept: 'application/json' },
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new AlertRequestError('NETWORK_ERROR', '无法连接告警服务，请重试。');
  }
  const trace = response.headers.get('x-trace-id') || undefined;
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new AlertRequestError('INVALID_RESPONSE', '告警服务返回了无法读取的数据，请重试。', trace, response.status); }
  if (!response.ok) {
    const parsedError = errorEnvelopeSchema.safeParse(body);
    if (parsedError.success) {
      const error = parsedError.data.error;
      throw new AlertRequestError(error.code, error.message, error.trace_id || trace, response.status);
    }
    throw new AlertRequestError('HTTP_ERROR', `告警请求失败（HTTP ${response.status}），请重试。`, trace, response.status);
  }
  const parsed = alertPageSchema.safeParse(body);
  if (!parsed.success || parsed.data.page !== filters.page || parsed.data.page_size !== filters.pageSize) {
    throw new AlertRequestError('INVALID_RESPONSE', '告警数据或分页格式不符合接口契约，请重试。', trace, response.status);
  }
  return parsed.data;
}
