import { z } from 'zod';
import { severityValues } from '../alerts/alertsContract';

const hashSchema = z.string().regex(/^[0-9a-f]{64}$/);
const eventSchema = z.object({
  event_id: z.string().min(1), source: z.string().min(1),
  observed_at: z.iso.datetime({ offset: true }), severity: z.enum(severityValues),
  event_type: z.string().min(1), raw: z.record(z.string(), z.unknown()),
  content_sha256: hashSchema,
});
const evidenceSchema = z.object({
  evidence_id: z.string().min(1), incident_id: z.string().min(1), event_id: z.string().min(1), source: z.string().min(1),
  observed_at: z.iso.datetime({ offset: true }), query: z.record(z.string(), z.unknown()),
  summary: z.string().min(1), content_sha256: hashSchema,
});

export const evidenceDetailSchema = z.object({
  evidence: evidenceSchema,
  raw_event: eventSchema,
  raw_access: z.literal('full'),
  integrity: z.object({
    algorithm: z.literal('sha256'), canonicalization: z.literal('evidencesoc-json-v1'),
    scope: z.literal('postgresql'), status: z.enum(['verified', 'mismatch', 'unavailable']),
    checked_at: z.iso.datetime({ offset: true }), calculated_sha256: hashSchema.nullable(),
    stored_event_sha256: hashSchema, stored_evidence_sha256: hashSchema,
  }),
}).superRefine((data, context) => {
  if (data.evidence.event_id !== data.raw_event.event_id) {
    context.addIssue({ code: 'custom', message: 'Evidence event does not match raw event.' });
  }
});

export type EvidenceDetail = z.infer<typeof evidenceDetailSchema>;

const errorEnvelopeSchema = z.object({ error: z.object({
  code: z.string(), message: z.string(), trace_id: z.string().nullable(),
}) });

export class EvidenceDetailRequestError extends Error {
  constructor(public code: string, message: string, public traceId?: string, public status?: number) {
    super(message);
    this.name = 'EvidenceDetailRequestError';
  }
}

export async function loadEvidenceDetail(incidentId: string, evidenceId: string, signal?: AbortSignal): Promise<EvidenceDetail> {
  let response: Response;
  try {
    response = await fetch(`/api/v1/incidents/${encodeURIComponent(incidentId)}/evidence/${encodeURIComponent(evidenceId)}`, {
      signal, cache: 'no-store', headers: { Accept: 'application/json' },
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new EvidenceDetailRequestError('NETWORK_ERROR', '无法连接证据服务，请重试。');
  }
  const trace = response.headers.get('x-trace-id') || undefined;
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new EvidenceDetailRequestError('INVALID_RESPONSE', '证据服务返回了无法读取的数据，请重试。', trace, response.status); }
  if (!response.ok) {
    const parsed = errorEnvelopeSchema.safeParse(body);
    if (parsed.success) {
      const { code, message, trace_id } = parsed.data.error;
      throw new EvidenceDetailRequestError(code, message, trace_id || trace, response.status);
    }
    throw new EvidenceDetailRequestError('HTTP_ERROR', `证据请求失败（HTTP ${response.status}），请重试。`, trace, response.status);
  }
  const parsed = evidenceDetailSchema.safeParse(body);
  if (!parsed.success || parsed.data.evidence.evidence_id !== evidenceId || parsed.data.evidence.incident_id !== incidentId) {
    throw new EvidenceDetailRequestError('INVALID_RESPONSE', '证据详情不符合接口契约，请重试。', trace, response.status);
  }
  return parsed.data;
}
