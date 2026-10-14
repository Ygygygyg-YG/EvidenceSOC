import { z } from 'zod';
import { evidenceSchema } from './incidentContract';

const businessId = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
const pageItemSchema = evidenceSchema.extend({ incident_id: businessId });
export type EvidencePageItem = z.infer<typeof pageItemSchema>;

export const evidencePageSchema = z.object({
  items: z.array(pageItemSchema), total: z.number().int().nonnegative(),
  page: z.number().int().positive(), page_size: z.number().int().min(1).max(200),
}).superRefine((page, context) => {
  if (page.items.length > page.total || page.items.length > page.page_size) {
    context.addIssue({ code: 'custom', message: '证据分页数量无效。' });
  }
  if (new Set(page.items.map((item) => item.evidence_id)).size !== page.items.length) {
    context.addIssue({ code: 'custom', message: '证据编号重复。' });
  }
});
export type EvidencePage = z.infer<typeof evidencePageSchema>;

const errorEnvelope = z.object({ error: z.object({
  code: z.string(), message: z.string(), trace_id: z.string().nullable(),
}) });

export class EvidencePageRequestError extends Error {
  constructor(public code: string, message: string, public traceId?: string, public status?: number) {
    super(message);
    this.name = 'EvidencePageRequestError';
  }
}

export async function loadEvidencePage(
  incidentId: string, page: number, pageSize: number, signal?: AbortSignal,
): Promise<EvidencePage> {
  if (!businessId.safeParse(incidentId).success || !Number.isSafeInteger(page) || page < 1
    || !Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 200) {
    throw new EvidencePageRequestError('INVALID_REQUEST', '证据分页参数无效。', undefined, 400);
  }
  let response: Response;
  try {
    response = await fetch(`/api/v1/incidents/${encodeURIComponent(incidentId)}/evidence?page=${page}&page_size=${pageSize}`, {
      signal, cache: 'no-store', headers: { Accept: 'application/json' },
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new EvidencePageRequestError('NETWORK_ERROR', '无法连接证据服务，请重试。');
  }
  const traceId = response.headers.get('x-trace-id') || undefined;
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new EvidencePageRequestError('INVALID_RESPONSE', '证据服务返回了无法读取的数据。', traceId, response.status); }
  if (!response.ok) {
    const parsed = errorEnvelope.safeParse(body);
    if (parsed.success) throw new EvidencePageRequestError(
      parsed.data.error.code, parsed.data.error.message, parsed.data.error.trace_id || traceId, response.status,
    );
    throw new EvidencePageRequestError('HTTP_ERROR', `证据请求失败（HTTP ${response.status}）。`, traceId, response.status);
  }
  const parsed = evidencePageSchema.safeParse(body);
  if (!parsed.success || parsed.data.page !== page || parsed.data.page_size !== pageSize
    || parsed.data.items.some((item) => item.incident_id !== incidentId)) {
    throw new EvidencePageRequestError('INVALID_RESPONSE', '证据列表不符合接口契约，请重试。', traceId, response.status);
  }
  return parsed.data;
}
