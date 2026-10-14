import { z } from 'zod';
import { severityValues, statusValues } from '../alerts/alertsContract';
import type { components } from '../../lib/api/generated';

type ApiIncident = components['schemas']['IncidentDetail'];
type ApiIncidentSummary = Pick<ApiIncident,
  'incident_id' | 'alert_id' | 'status' | 'created_at' | 'investigation_id' |
  'trace_id' | 'fallback_used' | 'stop_reason'> & {
    alerts: Pick<ApiIncident['alerts'][number], 'alert_id' | 'title' | 'severity'>[];
    evidence: Pick<ApiIncident['evidence'][number],
      'evidence_id' | 'event_id' | 'source' | 'observed_at' | 'query' | 'summary' | 'content_sha256'>[];
    attack_steps: Pick<ApiIncident['attack_steps'][number],
      'attack_step_id' | 'sequence' | 'phase' | 'technique_id' | 'description' | 'occurred_at' | 'evidence_ids'>[];
    runs: Pick<ApiIncident['runs'][number],
      'run_id' | 'agent_name' | 'status' | 'started_at' | 'finished_at' | 'evidence_ids'>[];
    origin: ApiIncident['origin'];
    classification: ApiIncident['classification'];
    response_plan: Pick<NonNullable<ApiIncident['response_plan']>, 'response_plan_id' | 'summary' | 'evidence_ids'> | null;
    validation_result: Pick<NonNullable<ApiIncident['validation_result']>, 'outcome' | 'summary' | 'checked_at'> | null;
  };

const alertSchema = z.object({
  alert_id: z.string().min(1), title: z.string().min(1), severity: z.enum(severityValues),
});
export const evidenceSchema = z.object({
  evidence_id: z.string().min(1), event_id: z.string().min(1),
  source: z.string().min(1), observed_at: z.iso.datetime({ offset: true }),
  query: z.record(z.string(), z.unknown()), summary: z.string().min(1),
  content_sha256: z.string().regex(/^[0-9a-f]{64}$/),
});
const stepSchema = z.object({
  attack_step_id: z.string().min(1), sequence: z.number().int(),
  phase: z.string().nullable(), technique_id: z.string().nullable().optional(),
  description: z.string().min(1), occurred_at: z.iso.datetime({ offset: true }).nullable(),
  evidence_ids: z.array(z.string().min(1)),
});
const runSchema = z.object({
  run_id: z.string().min(1), agent_name: z.string().min(1),
  status: z.enum(['pending', 'running', 'completed', 'failed']),
  started_at: z.iso.datetime({ offset: true }), finished_at: z.iso.datetime({ offset: true }).nullable(),
  evidence_ids: z.array(z.string().min(1)),
});

const originSchema = z.object({
  observed_source_ip: z.string().nullable(), entry_host: z.string().nullable(),
  entry_service: z.string().nullable(), first_seen_at: z.iso.datetime({ offset: true }).nullable(),
  source_scope: z.enum(['external', 'internal', 'unknown']), confidence: z.number().min(0).max(1),
  evidence_ids: z.array(z.string().min(1)),
});
const classificationSchema = z.object({
  primary_type: z.string().nullable(), attack_types: z.array(z.string()),
  dataset_labels: z.array(z.string()).optional(), attack_phase: z.string().nullable(),
  technique_ids: z.array(z.string()), confidence: z.number().min(0).max(1),
  evidence_ids: z.array(z.string().min(1)),
});

export const incidentSummarySchema = z.object({
  incident_id: z.string().min(1), alert_id: z.string().min(1), status: z.enum(statusValues),
  created_at: z.iso.datetime({ offset: true }), investigation_id: z.string().nullable(),
  trace_id: z.string().nullable(),
  alerts: z.array(alertSchema), evidence: z.array(evidenceSchema),
  attack_steps: z.array(stepSchema), runs: z.array(runSchema),
  origin: originSchema.nullable(), classification: classificationSchema.nullable(),
  response_plan: z.object({ response_plan_id: z.string().min(1), summary: z.string(), evidence_ids: z.array(z.string()) }).nullable(),
  validation_result: z.object({ outcome: z.enum(['success', 'failure', 'insufficient_evidence']),
    summary: z.string(), checked_at: z.iso.datetime({ offset: true }) }).nullable(),
  fallback_used: z.boolean(), stop_reason: z.string().nullable(),
}) satisfies z.ZodType<ApiIncidentSummary>;

export type IncidentSummary = z.infer<typeof incidentSummarySchema>;

const errorEnvelopeSchema = z.object({ error: z.object({
  code: z.string(), message: z.string(), trace_id: z.string().nullable(),
}) });

export class IncidentRequestError extends Error {
  constructor(public code: string, message: string, public traceId?: string, public status?: number) {
    super(message);
    this.name = 'IncidentRequestError';
  }
}

export async function loadIncident(id: string, signal?: AbortSignal): Promise<IncidentSummary> {
  let response: Response;
  try {
    response = await fetch(`/api/v1/incidents/${encodeURIComponent(id)}`, {
      signal, cache: 'no-store', headers: { Accept: 'application/json' },
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new IncidentRequestError('NETWORK_ERROR', '无法连接案件服务，请重试。');
  }
  const trace = response.headers.get('x-trace-id') || undefined;
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new IncidentRequestError('INVALID_RESPONSE', '案件服务返回了无法读取的数据，请重试。', trace, response.status); }
  if (!response.ok) {
    const parsed = errorEnvelopeSchema.safeParse(body);
    if (parsed.success) {
      const { code, message, trace_id } = parsed.data.error;
      throw new IncidentRequestError(code, message, trace_id || trace, response.status);
    }
    throw new IncidentRequestError('HTTP_ERROR', `案件请求失败（HTTP ${response.status}），请重试。`, trace, response.status);
  }
  const parsed = incidentSummarySchema.safeParse(body);
  if (!parsed.success || parsed.data.incident_id !== id) {
    throw new IncidentRequestError('INVALID_RESPONSE', '案件数据格式不符合接口契约，请重试。', trace, response.status);
  }
  return parsed.data;
}
