import { z } from 'zod';
import type { components } from '@/lib/api/generated';
import { severityValues, statusValues } from '../alerts/alertsContract';

const businessId = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
const dateTime = z.iso.datetime({ offset: true });
const decisionStates = ['pending', 'submitting', 'approved', 'rejected'] as const;
const decisionActions = ['approve', 'reject'] as const;
export const decisionFilters = ['pending', 'approved', 'rejected'] as const;
export const pageSizeOptions = [20, 50, 100] as const;

const eventFilterKeys = new Set(['source', 'event_type', 'severity', 'source_ip', 'destination_ip', 'host', 'service']);
const verificationQuerySchema = z.object({
  filters: z.record(z.string(), z.string().trim().min(1)).refine(
    (filters) => Object.keys(filters).length > 0 && Object.keys(filters).every((key) => eventFilterKeys.has(key)),
  ),
  time_from: dateTime.optional(),
  time_to: dateTime.optional(),
  limit: z.number().int().min(1).max(200).optional(),
}).strict().superRefine((query, context) => {
  if (Boolean(query.time_from) !== Boolean(query.time_to)) {
    context.addIssue({ code: 'custom', message: '验证查询必须同时指定起止时间。' });
  } else if (query.time_from && query.time_to && Date.parse(query.time_from) >= Date.parse(query.time_to)) {
    context.addIssue({ code: 'custom', message: '验证查询的时间范围无效。' });
  }
});
const simulatedActionSchema = z.object({
  action: z.enum(['block_ip_simulated', 'isolate_host_simulated', 'disable_account_simulated']),
  target: z.string().trim().min(1).max(255), risk: z.string().trim().min(1), impact: z.string().trim().min(1),
  preview: z.string().trim().min(1), rollback: z.string().trim().min(1),
  verification_query: verificationQuerySchema,
  action_id: z.string().regex(/^ACT-[A-Za-z0-9-]{1,60}$/).nullish().default(null),
  type: z.enum(['block_ip_simulated', 'isolate_host_simulated', 'disable_account_simulated']).nullish().default(null),
  parameters: z.record(z.string(), z.string()).nullish().default(null),
  expected_effect: z.string().trim().min(1).nullish().default(null),
  rollback_ref: businessId.nullish().default(null),
  evidence_ids: z.array(businessId).min(1).nullish().default(null),
}).strict().superRefine((action, context) => {
  if (action.type && action.type !== action.action) {
    context.addIssue({ code: 'custom', message: '动作类型与模拟类型不一致。' });
  }
  const targetKey = action.action === 'block_ip_simulated' ? 'source_ip'
    : action.action === 'isolate_host_simulated' ? 'host' : 'account';
  if (action.parameters && (Object.keys(action.parameters).length !== 1 || action.parameters[targetKey] !== action.target)) {
    context.addIssue({ code: 'custom', message: '动作参数必须仅包含模拟目标。' });
  }
  if (action.action === 'block_ip_simulated' &&
      !z.ipv4().or(z.ipv6()).safeParse(action.target).success) {
    context.addIssue({ code: 'custom', message: '模拟阻断目标必须是 IP 地址。' });
  }
  if (action.action !== 'block_ip_simulated' && !/^[A-Za-z0-9_.@:-]+$/.test(action.target)) {
    context.addIssue({ code: 'custom', message: '模拟目标必须是主机或账号标识。' });
  }
  const targetFilter = action.action === 'block_ip_simulated' ? 'source_ip'
    : action.action === 'isolate_host_simulated' ? 'host' : null;
  if (targetFilter && action.verification_query.filters[targetFilter] !== action.target) {
    context.addIssue({ code: 'custom', message: '验证查询必须限定模拟目标。' });
  }
});
const rollbackStepSchema = z.object({
  step_id: businessId, description: z.string().min(1), target: z.string().min(1),
  expected_result: z.string().min(1), evidence_ids: z.array(businessId).min(1),
});
const validationCheckSchema = rollbackStepSchema.omit({ step_id: true }).extend({
  check_id: businessId, query: z.record(z.string(), z.unknown()),
});

const responsePlanSchema = z.object({
  response_plan_id: businessId, incident_id: businessId, summary: z.string().min(1),
  actions: z.array(simulatedActionSchema).min(1), created_at: dateTime,
  requires_approval: z.literal(true), evidence_ids: z.array(businessId).min(1),
  execution_mode: z.literal('simulation'),
  risk_level: z.enum(['low', 'medium', 'high', 'critical']).nullable(),
  risk_reason: z.string().nullable(), affected_assets: z.array(z.string().min(1)),
  business_impact: z.string().nullable(), expires_at: dateTime.nullable(),
  rollback_steps: z.array(rollbackStepSchema), validation_checks: z.array(validationCheckSchema),
}) satisfies z.ZodType<components['schemas']['ResponsePlan']>;

export const responseItemSchema = responsePlanSchema.extend({
  plan_version: z.string().regex(/^[a-f0-9]{64}$/),
  is_expired: z.boolean(),
  investigation_id: businessId.nullable(), alert_id: businessId, alert_title: z.string().min(1),
  severity: z.enum(severityValues), incident_status: z.enum(statusValues),
  decision_state: z.enum(decisionStates), is_current: z.boolean(),
});
export type ResponsePlanItem = z.infer<typeof responseItemSchema>;
export type DecisionState = ResponsePlanItem['decision_state'];
export type DecisionFilter = typeof decisionFilters[number];

const approvalSchema = z.object({
  approval_id: businessId, response_plan_id: businessId, decision: z.enum(['approved', 'rejected']),
  reason: z.string().min(1), decided_by: z.string().min(1), decided_at: dateTime,
}) satisfies z.ZodType<components['schemas']['ApprovalRecord']>;
const validationSchema = z.object({
  validation_id: businessId, response_plan_id: businessId,
  outcome: z.enum(['success', 'failure', 'insufficient_evidence']),
  summary: z.string(), checked_at: dateTime, evidence_ids: z.array(businessId).min(1),
  time_from: dateTime.nullish().default(null), time_to: dateTime.nullish().default(null),
  checks: z.array(z.object({
    check_id: businessId, condition: z.record(z.string(), z.unknown()),
    outcome: z.enum(['success', 'failure', 'insufficient_evidence']),
    evidence_ids: z.array(businessId), explanation: z.string(),
  })).default([]),
}) satisfies z.ZodType<components['schemas']['ValidationResult']>;
const simulationSchema = simulatedActionSchema.extend({
  execution_id: z.string().regex(/^[A-Za-z0-9_-]{1,64}:[0-9]+$/),
  simulated: z.literal(true), status: z.string().min(1), outcome: z.string().min(1),
}) satisfies z.ZodType<components['schemas']['SimulationResult']>;
const simulationExecutionSchema = z.object({
  simulation_id: businessId, response_plan_id: businessId,
  plan_version: z.string().regex(/^[a-f0-9]{64}$/),
  status: z.enum(['pending', 'running', 'completed', 'failed']),
  started_at: dateTime.nullable(), finished_at: dateTime.nullable(),
  action_results: z.array(z.object({
    action_id: businessId, outcome: z.enum(['success', 'failure', 'skipped']),
    description: z.string().min(1), started_at: dateTime.nullable(), finished_at: dateTime.nullable(),
  })), error: z.string().nullable(),
});

export const responseDetailSchema = responseItemSchema.extend({
  approval: approvalSchema.nullable(), validation_result: validationSchema.nullable(),
  simulation: z.array(simulationSchema), pending_decision: z.enum(['approved', 'rejected']).nullable(),
  simulation_execution: simulationExecutionSchema.nullable().optional(),
  available_actions: z.array(z.enum(decisionActions)),
}).superRefine((data, context) => {
  if (data.approval && data.approval.response_plan_id !== data.response_plan_id) {
    context.addIssue({ code: 'custom', message: '审批记录不属于当前方案。' });
  }
  if (data.validation_result && data.validation_result.response_plan_id !== data.response_plan_id) {
    context.addIssue({ code: 'custom', message: '验证结果不属于当前方案。' });
  }
  if (data.simulation.some((result) => !result.execution_id.startsWith(`${data.response_plan_id}:`))) {
    context.addIssue({ code: 'custom', message: '模拟结果不属于当前方案。' });
  }
  if (new Set(data.available_actions).size !== data.available_actions.length) {
    context.addIssue({ code: 'custom', message: '审批动作重复。' });
  }
  const actionIds = data.actions.flatMap((action) => action.action_id ? [action.action_id] : []);
  if (new Set(actionIds).size !== actionIds.length) {
    context.addIssue({ code: 'custom', message: '动作编号重复。' });
  }
  for (const action of data.actions) {
    if (action.rollback_ref && !data.rollback_steps.some((step) => step.step_id === action.rollback_ref)) {
      context.addIssue({ code: 'custom', message: '动作引用的回滚步骤不存在。' });
    }
    if (action.evidence_ids?.some((id) => !data.evidence_ids.includes(id))) {
      context.addIssue({ code: 'custom', message: '动作引用了方案以外的证据。' });
    }
  }
  if (data.simulation_execution) {
    const execution = data.simulation_execution;
    if (execution.response_plan_id !== data.response_plan_id || execution.plan_version !== data.plan_version) {
      context.addIssue({ code: 'custom', message: '模拟执行不属于当前方案版本。' });
    }
    const resultIds = execution.action_results.map((result) => result.action_id);
    if (new Set(resultIds).size !== resultIds.length || resultIds.some((id) => !actionIds.includes(id))) {
      context.addIssue({ code: 'custom', message: '模拟结果引用了未知或重复的动作。' });
    }
  }
  if (data.validation_result) {
    const checkIds = data.validation_result.checks?.map((check) => check.check_id) ?? [];
    if (new Set(checkIds).size !== checkIds.length || checkIds.some((id) => !data.validation_checks.some((check) => check.check_id === id))) {
      context.addIssue({ code: 'custom', message: '验证结果引用了未知或重复的条件。' });
    }
    if (data.validation_result.checks?.some((check) => check.evidence_ids.some((id) => !data.evidence_ids.includes(id)))) {
      context.addIssue({ code: 'custom', message: '验证结果引用了方案以外的证据。' });
    }
  }
});
export type ResponsePlanDetail = z.infer<typeof responseDetailSchema>;

export const responsePageSchema = z.object({
  items: z.array(responseItemSchema), total: z.number().int().nonnegative(),
  page: z.number().int().positive(), page_size: z.number().int().min(1).max(200),
}).superRefine((page, context) => {
  if (page.items.length > page.page_size || page.items.length > page.total) {
    context.addIssue({ code: 'custom', message: '响应方案分页数量无效。' });
  }
  if (new Set(page.items.map((item) => item.response_plan_id)).size !== page.items.length) {
    context.addIssue({ code: 'custom', message: '响应方案编号重复。' });
  }
});
export type ResponsePlanPage = z.infer<typeof responsePageSchema>;

const acceptedSchema = z.object({
  response_plan_id: businessId, investigation_id: businessId, incident_id: businessId,
  trace_id: z.string().min(1), decision: z.enum(['approved', 'rejected']), status: z.literal('accepted'),
}) satisfies z.ZodType<components['schemas']['DecisionAccepted']>;
export type DecisionAccepted = z.infer<typeof acceptedSchema>;

const renewalAcceptedSchema = z.object({
  response_plan_id: businessId, investigation_id: businessId, incident_id: businessId,
  trace_id: z.string().min(1), status: z.literal('accepted'), stream_url: z.string().min(1),
});
export type PlanRenewalAccepted = z.infer<typeof renewalAcceptedSchema>;

const errorEnvelope = z.object({ error: z.object({
  code: z.string(), message: z.string(), trace_id: z.string().nullable(),
}) });

export type ResponseFilters = { page: number; pageSize: number; decisionState?: DecisionFilter };
export function readResponseFilters(params: Pick<URLSearchParams, 'get'>): ResponseFilters {
  const page = Number(params.get('page') ?? 1);
  const pageSize = Number(params.get('page_size') ?? 20);
  const decision = params.get('decision_state');
  return {
    page: Number.isSafeInteger(page) && page >= 1 ? page : 1,
    pageSize: pageSizeOptions.find((size) => size === pageSize) ?? 20,
    decisionState: decisionFilters.find((state) => state === decision),
  };
}

export function buildResponseQuery(filters: ResponseFilters): string {
  const query = new URLSearchParams({ page: String(filters.page), page_size: String(filters.pageSize) });
  if (filters.decisionState) query.set('decision_state', filters.decisionState);
  return query.toString();
}

export class ResponsePlanRequestError extends Error {
  constructor(public code: string, message: string, public traceId?: string, public status?: number) {
    super(message);
    this.name = 'ResponsePlanRequestError';
  }
}

async function readJson(response: Response): Promise<unknown> {
  const traceId = response.headers.get('x-trace-id') || undefined;
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new ResponsePlanRequestError('INVALID_RESPONSE', '响应服务返回了无法读取的数据，请重试。', traceId, response.status); }
  if (!response.ok) {
    const parsed = errorEnvelope.safeParse(body);
    if (parsed.success) {
      throw new ResponsePlanRequestError(parsed.data.error.code, parsed.data.error.message,
        parsed.data.error.trace_id || traceId, response.status);
    }
    throw new ResponsePlanRequestError('HTTP_ERROR', `请求失败（HTTP ${response.status}），请重试。`, traceId, response.status);
  }
  return body;
}

async function get(path: string, signal?: AbortSignal): Promise<{ body: unknown; response: Response }> {
  let response: Response;
  try {
    response = await fetch(path, { signal, cache: 'no-store', headers: { Accept: 'application/json' } });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new ResponsePlanRequestError('NETWORK_ERROR', '无法连接响应服务，请重试。');
  }
  return { body: await readJson(response), response };
}

export async function loadResponsePlans(filters: ResponseFilters, signal?: AbortSignal): Promise<ResponsePlanPage> {
  const { body, response } = await get(`/api/v1/response-plans?${buildResponseQuery(filters)}`, signal);
  const parsed = responsePageSchema.safeParse(body);
  if (!parsed.success || parsed.data.page !== filters.page || parsed.data.page_size !== filters.pageSize) {
    throw new ResponsePlanRequestError('INVALID_RESPONSE', '响应列表不符合接口契约，请重试。', response.headers.get('x-trace-id') || undefined, response.status);
  }
  return parsed.data;
}

export async function loadResponseDetail(id: string, signal?: AbortSignal): Promise<ResponsePlanDetail> {
  if (!businessId.safeParse(id).success) throw new ResponsePlanRequestError('INVALID_PLAN_ID', '响应方案编号无效。', undefined, 400);
  const { body, response } = await get(`/api/v1/response-plans/${encodeURIComponent(id)}`, signal);
  const parsed = responseDetailSchema.safeParse(body);
  if (!parsed.success || parsed.data.response_plan_id !== id) {
    throw new ResponsePlanRequestError('INVALID_RESPONSE', '响应详情不符合接口契约，请刷新。', response.headers.get('x-trace-id') || undefined, response.status);
  }
  return parsed.data;
}

export async function submitResponseDecision(
  id: string, action: 'approve' | 'reject',
  input: { plan_version: string; reason: string }, idempotencyKey: string,
): Promise<DecisionAccepted> {
  if (!businessId.safeParse(id).success) throw new ResponsePlanRequestError('INVALID_PLAN_ID', '响应方案编号无效。', undefined, 400);
  if (!/^[a-f0-9]{64}$/.test(input.plan_version)) throw new ResponsePlanRequestError('INVALID_PLAN_VERSION', '响应方案版本无效，请刷新详情。', undefined, 400);
  if (!/^[\x21-\x7e]{1,255}$/.test(idempotencyKey)) throw new ResponsePlanRequestError('INVALID_IDEMPOTENCY_KEY', '提交标识无效，请刷新详情。', undefined, 400);
  const reason = input.reason.trim();
  if (!reason || reason.length > 2000) throw new ResponsePlanRequestError('INVALID_REASON', '请填写 1 至 2000 字的决定理由。', undefined, 400);
  let response: Response;
  try {
    response = await fetch(`/api/v1/response-plans/${encodeURIComponent(id)}/${action}`, {
      method: 'POST', cache: 'no-store', headers: {
        Accept: 'application/json', 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey,
      },
      body: JSON.stringify({ plan_version: input.plan_version, reason }),
    });
  } catch {
    throw new ResponsePlanRequestError('NETWORK_ERROR', '提交结果未知。请刷新方案详情确认，勿直接重复提交。');
  }
  const body = await readJson(response);
  const parsed = acceptedSchema.safeParse(body);
  const expected = action === 'approve' ? 'approved' : 'rejected';
  if (response.status !== 202 || !parsed.success || parsed.data.response_plan_id !== id || parsed.data.decision !== expected) {
    throw new ResponsePlanRequestError('INVALID_RESPONSE', '提交结果无法确认。请刷新方案详情，不要重复提交。', response.headers.get('x-trace-id') || undefined, response.status);
  }
  return parsed.data;
}

export async function submitPlanRenewal(
  id: string, planVersion: string, idempotencyKey: string,
): Promise<PlanRenewalAccepted> {
  if (!businessId.safeParse(id).success) throw new ResponsePlanRequestError('INVALID_PLAN_ID', '响应方案编号无效。', undefined, 400);
  if (!/^[a-f0-9]{64}$/.test(planVersion)) throw new ResponsePlanRequestError('INVALID_PLAN_VERSION', '响应方案版本无效，请刷新详情。', undefined, 400);
  if (!/^[\x21-\x7e]{1,255}$/.test(idempotencyKey)) throw new ResponsePlanRequestError('INVALID_IDEMPOTENCY_KEY', '提交标识无效，请刷新详情。', undefined, 400);
  let response: Response;
  try {
    response = await fetch(`/api/v1/response-plans/${encodeURIComponent(id)}/renew`, {
      method: 'POST', cache: 'no-store', headers: {
        Accept: 'application/json', 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey,
      },
      body: JSON.stringify({ plan_version: planVersion }),
    });
  } catch {
    throw new ResponsePlanRequestError('NETWORK_ERROR', '续办结果未知。请刷新方案详情确认，勿直接重复提交。');
  }
  const body = await readJson(response);
  const parsed = renewalAcceptedSchema.safeParse(body);
  if (![200, 202].includes(response.status) || !parsed.success || parsed.data.response_plan_id !== id) {
    throw new ResponsePlanRequestError('INVALID_RESPONSE', '续办结果无法确认。请刷新方案详情。', response.headers.get('x-trace-id') || undefined, response.status);
  }
  return parsed.data;
}
