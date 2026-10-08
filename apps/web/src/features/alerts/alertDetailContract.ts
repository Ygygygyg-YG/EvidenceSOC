import { z } from 'zod';
import type { components } from '@/lib/api/generated';
import { AlertRequestError, severityValues, statusValues } from './alertsContract';

const externalId = z.string().min(1).max(64);
const businessId = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);

export const alertDetailSchema = z.object({
  alert_id: externalId,
  title: z.string().min(1),
  severity: z.enum(severityValues),
  created_at: z.iso.datetime({ offset: true }),
  event_ids: z.array(externalId).min(1),
  status: z.enum(statusValues),
  execution_mode: z.enum(['rules', 'model']),
  incident_id: businessId.nullable(),
  investigation_id: businessId.nullable(),
  events: z.array(z.object({
    event_id: externalId,
    source: z.string().min(1),
    observed_at: z.iso.datetime({ offset: true }),
    severity: z.enum(severityValues),
    event_type: z.string().min(1),
  })),
}).superRefine((value, context) => {
  if (value.events.length !== value.event_ids.length || value.events.some((event, index) => event.event_id !== value.event_ids[index])) {
    context.addIssue({ code: 'custom', message: '关联事件与告警不一致。' });
  }
  if (value.investigation_id && !value.incident_id) {
    context.addIssue({ code: 'custom', message: '调查缺少关联案件。' });
  }
}) satisfies z.ZodType<components['schemas']['AlertDetail']>;

export type AlertDetailData = z.infer<typeof alertDetailSchema>;

const acceptedSchema = z.object({
  investigation_id: businessId,
  incident_id: businessId,
  trace_id: z.string().min(1),
  status: z.enum(statusValues),
  stream_url: z.string().regex(/^\/api\/v1\/investigations\/[A-Za-z0-9_-]{1,64}\/stream$/),
}) satisfies z.ZodType<components['schemas']['InvestigationAccepted']>;

export type InvestigationAcceptedData = z.infer<typeof acceptedSchema>;

const errorEnvelope = z.object({ error: z.object({
  code: z.string(), message: z.string(), trace_id: z.string().nullable(),
}) });

async function readJson(response: Response): Promise<unknown> {
  const trace = response.headers.get('x-trace-id') || undefined;
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new AlertRequestError('INVALID_RESPONSE', '服务返回了无法读取的数据，请重试。', trace, response.status); }
  if (!response.ok) {
    const parsed = errorEnvelope.safeParse(body);
    if (parsed.success) {
      throw new AlertRequestError(parsed.data.error.code, parsed.data.error.message,
        parsed.data.error.trace_id || trace, response.status);
    }
    throw new AlertRequestError('HTTP_ERROR', `请求失败（HTTP ${response.status}），请重试。`, trace, response.status);
  }
  return body;
}

export async function loadAlertDetail(id: string, signal?: AbortSignal): Promise<AlertDetailData> {
  if (!externalId.safeParse(id).success) throw new AlertRequestError('INVALID_ALERT_ID', '告警编号无效。', undefined, 400);
  let response: Response;
  try {
    response = await fetch(`/api/v1/alerts/${encodeURIComponent(id)}`, {
      signal, cache: 'no-store', headers: { Accept: 'application/json' },
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new AlertRequestError('NETWORK_ERROR', '无法连接告警服务，请重试。');
  }
  const body = await readJson(response);
  const parsed = alertDetailSchema.safeParse(body);
  if (!parsed.success || parsed.data.alert_id !== id) {
    throw new AlertRequestError('INVALID_RESPONSE', '告警详情不符合接口契约，请重试。', response.headers.get('x-trace-id') || undefined, response.status);
  }
  return parsed.data;
}

export async function startInvestigation(
  alertId: string, mode: 'rules' | 'model', idempotencyKey: string,
): Promise<InvestigationAcceptedData> {
  if (!externalId.safeParse(alertId).success) throw new AlertRequestError('INVALID_ALERT_ID', '告警编号无效。', undefined, 400);
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(idempotencyKey)) {
    throw new AlertRequestError('INVALID_REQUEST', '启动调查的幂等键无效。', undefined, 400);
  }
  let response: Response;
  try {
    response = await fetch('/api/v1/investigations', {
      method: 'POST', cache: 'no-store',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ alert_id: alertId, mode }),
    });
  } catch {
    throw new AlertRequestError('NETWORK_ERROR', '无法连接调查服务。请刷新告警详情，确认是否已创建调查。');
  }
  const body = await readJson(response);
  const parsed = acceptedSchema.safeParse(body);
  if (!parsed.success || parsed.data.stream_url !== `/api/v1/investigations/${parsed.data.investigation_id}/stream`) {
    throw new AlertRequestError('INVALID_RESPONSE', '调查服务返回了无效的案件编号。请刷新告警详情。', response.headers.get('x-trace-id') || undefined, response.status);
  }
  return parsed.data;
}
