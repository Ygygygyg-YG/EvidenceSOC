import { z } from 'zod';
import { statusValues, type IncidentStatus } from '../alerts/alertsContract';

export const validationOutcomes = ['success', 'failure', 'insufficient_evidence'] as const;
export const validationOutcomeLabels: Record<(typeof validationOutcomes)[number], string> = {
  success: '验证成功', failure: '验证失败', insufficient_evidence: '证据不足',
};

const itemSchema = z.object({
  incident_id: z.string().min(1), investigation_id: z.string().min(1).nullable(),
  alert_id: z.string().min(1), alert_title: z.string().min(1),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  status: z.enum(statusValues), created_at: z.iso.datetime({ offset: true }),
  evidence_count: z.number().int().nonnegative(),
  validation_outcome: z.enum(validationOutcomes).nullable(),
});

export const incidentPageSchema = z.object({
  items: z.array(itemSchema), total: z.number().int().nonnegative(),
  page: z.number().int().positive(), page_size: z.number().int().min(1).max(200),
}).superRefine((data, context) => {
  if (data.items.length > data.total || data.items.length > data.page_size
    || new Set(data.items.map((item) => item.incident_id)).size !== data.items.length) {
    context.addIssue({ code: 'custom', message: 'Invalid incident page.' });
  }
});

export type IncidentPage = z.infer<typeof incidentPageSchema>;
export type IncidentListItem = IncidentPage['items'][number];
export type IncidentFilters = { page: number; pageSize: number; status?: IncidentStatus;
  risk?: 'high'; timeFrom?: string; timeTo?: string };
export const pageSizeOptions = [20, 50, 100] as const;

function validTimeRange(from?: string | null, to?: string | null): from is string {
  return Boolean(from && to && z.iso.datetime({ offset: true }).safeParse(from).success
    && z.iso.datetime({ offset: true }).safeParse(to).success && Date.parse(from) < Date.parse(to));
}

export function readIncidentFilters(params: Pick<URLSearchParams, 'get'>): IncidentFilters {
  const page = Number(params.get('page') ?? 1);
  const pageSize = Number(params.get('page_size') ?? 20);
  const status = params.get('status');
  const risk = params.get('risk');
  const timeFrom = params.get('time_from');
  const timeTo = params.get('time_to');
  return {
    page: Number.isSafeInteger(page) && page >= 1 ? page : 1,
    pageSize: pageSizeOptions.some((value) => value === pageSize) ? pageSize : 20,
    status: statusValues.find((value) => value === status),
    risk: risk === 'high' ? 'high' : undefined,
    timeFrom: validTimeRange(timeFrom, timeTo) ? timeFrom! : undefined,
    timeTo: validTimeRange(timeFrom, timeTo) ? timeTo! : undefined,
  };
}

export function buildIncidentsQuery(filters: IncidentFilters): string {
  const query = new URLSearchParams({ page: String(filters.page), page_size: String(filters.pageSize) });
  if (filters.status) query.set('status', filters.status);
  if (filters.risk) query.set('risk', filters.risk);
  if (validTimeRange(filters.timeFrom, filters.timeTo)) {
    query.set('time_from', filters.timeFrom!);
    query.set('time_to', filters.timeTo!);
  }
  return query.toString();
}

export function incidentDetailHref(id: string, filters: IncidentFilters): string {
  return `/incidents/${encodeURIComponent(id)}?from=${encodeURIComponent(buildIncidentsQuery(filters))}`;
}

export function incidentListReturnHref(from?: string | null): string {
  return from ? `/incidents?${buildIncidentsQuery(readIncidentFilters(new URLSearchParams(from)))}` : '/alerts';
}

export class IncidentsRequestError extends Error {
  constructor(public code: string, message: string, public traceId?: string, public status?: number) {
    super(message);
    this.name = 'IncidentsRequestError';
  }
}

const errorEnvelope = z.object({ error: z.object({
  code: z.string(), message: z.string(), trace_id: z.string().nullable(),
}) });

export async function loadIncidents(filters: IncidentFilters, signal?: AbortSignal): Promise<IncidentPage> {
  let response: Response;
  try {
    response = await fetch(`/api/v1/incidents?${buildIncidentsQuery(filters)}`, {
      signal, cache: 'no-store', headers: { Accept: 'application/json' },
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new IncidentsRequestError('NETWORK_ERROR', '无法连接案件服务，请重试。');
  }
  const trace = response.headers.get('x-trace-id') || undefined;
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new IncidentsRequestError('INVALID_RESPONSE', '案件服务返回了无法读取的数据。', trace, response.status); }
  if (!response.ok) {
    const parsed = errorEnvelope.safeParse(body);
    if (parsed.success) throw new IncidentsRequestError(parsed.data.error.code, parsed.data.error.message,
      parsed.data.error.trace_id || trace, response.status);
    throw new IncidentsRequestError('HTTP_ERROR', `案件请求失败（HTTP ${response.status}）。`, trace, response.status);
  }
  const parsed = incidentPageSchema.safeParse(body);
  if (!parsed.success || parsed.data.page !== filters.page || parsed.data.page_size !== filters.pageSize) {
    throw new IncidentsRequestError('INVALID_RESPONSE', '案件列表或分页格式不符合接口契约。', trace, response.status);
  }
  return parsed.data;
}
