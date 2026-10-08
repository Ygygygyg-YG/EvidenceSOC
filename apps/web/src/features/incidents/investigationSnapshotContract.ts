import { z } from 'zod';
import { IncidentRequestError, incidentSummarySchema } from './incidentContract';

const decimal = z.string().regex(/^(0|[1-9][0-9]*)$/);
const dateTime = z.iso.datetime({ offset: true });
const identifier = /^[A-Za-z0-9_-]{1,64}$/;

export const attackGraphSchema = z.object({
  revision: decimal,
  generated_at: dateTime,
  nodes: z.array(z.object({
    step_id: z.string().regex(identifier), sequence: z.number().int().nonnegative(),
    phase: z.string().nullable(), description: z.string().min(1),
    host: z.string().nullable(), service: z.string().nullable(), observed_at: dateTime.nullable(),
    technique_ids: z.array(z.string()), confidence: z.number().min(0).max(1).nullable(),
    evidence_ids: z.array(z.string()),
    support_status: z.enum(['supported', 'candidate', 'insufficient']),
  })),
  edges: z.array(z.object({
    edge_id: z.string().regex(identifier), source_step_id: z.string().regex(identifier),
    target_step_id: z.string().regex(identifier), relation: z.string().min(1),
    description: z.string().nullable(), confidence: z.number().min(0).max(1).nullable(),
    evidence_ids: z.array(z.string()),
    support_status: z.enum(['supported', 'candidate', 'insufficient']),
  })),
}).superRefine((graph, context) => {
  const nodes = new Set(graph.nodes.map((node) => node.step_id));
  if (nodes.size !== graph.nodes.length || graph.edges.some((edge) =>
    !nodes.has(edge.source_step_id) || !nodes.has(edge.target_step_id) || edge.source_step_id === edge.target_step_id)) {
    context.addIssue({ code: 'custom', message: '攻击图谱包含无效关系。' });
  }
});
export type AttackGraphData = z.infer<typeof attackGraphSchema>;

export const investigationSnapshotSchema = incidentSummarySchema.extend({
  investigation_id: z.string().regex(identifier),
  revision: decimal,
  stream_cursor: decimal,
  updated_at: dateTime,
  mode: z.enum(['rules', 'model']),
  available_actions: z.array(z.string()),
  attack_graph: attackGraphSchema,
});
export type InvestigationSnapshot = z.infer<typeof investigationSnapshotSchema>;

const errorEnvelope = z.object({ error: z.object({
  code: z.string(), message: z.string(), trace_id: z.string().nullable(),
}) });

export async function loadInvestigationSnapshot(id: string, signal?: AbortSignal): Promise<InvestigationSnapshot> {
  if (!identifier.test(id)) throw new IncidentRequestError('INVALID_INVESTIGATION_ID', '调查编号无效。', undefined, 400);
  let response: Response;
  try {
    response = await fetch(`/api/v1/investigations/${encodeURIComponent(id)}`, {
      signal, cache: 'no-store', headers: { Accept: 'application/json' },
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new IncidentRequestError('NETWORK_ERROR', '无法连接调查快照服务，请重试。');
  }
  const trace = response.headers.get('x-trace-id') || undefined;
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new IncidentRequestError('INVALID_RESPONSE', '调查快照返回了无法读取的数据。', trace, response.status); }
  if (!response.ok) {
    const parsed = errorEnvelope.safeParse(body);
    if (parsed.success) throw new IncidentRequestError(parsed.data.error.code, parsed.data.error.message,
      parsed.data.error.trace_id || trace, response.status);
    throw new IncidentRequestError('HTTP_ERROR', `调查快照请求失败（HTTP ${response.status}）。`, trace, response.status);
  }
  const parsed = investigationSnapshotSchema.safeParse(body);
  if (!parsed.success || parsed.data.investigation_id !== id) {
    throw new IncidentRequestError('INVALID_RESPONSE', '调查快照不符合接口契约。', trace, response.status);
  }
  return parsed.data;
}
