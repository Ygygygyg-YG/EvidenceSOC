import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildResponseQuery, loadResponseDetail, loadResponsePlans, readResponseFilters,
  responseDetailSchema, responsePageSchema, submitResponseDecision,
  submitPlanRenewal,
} from './responseContract';

const action = {
  action: 'block_ip_simulated', target: '198.51.100.42', risk: '低风险', impact: '只影响样例流量',
  preview: '模拟阻断该来源', rollback: '撤销模拟规则', verification_query: { filters: { source_ip: '198.51.100.42' } },
};
const planVersion = 'a'.repeat(64);
const item = {
  response_plan_id: 'RP-123', incident_id: 'IN-123', investigation_id: 'IV-123',
  alert_id: 'AL-123', alert_title: '可疑来源访问', severity: 'high', incident_status: 'awaiting_approval',
  summary: '限制异常请求来源', actions: [action], created_at: '2026-09-29T02:00:00Z',
  requires_approval: true, evidence_ids: ['EV-123'], decision_state: 'pending', is_current: true,
  execution_mode: 'simulation', risk_level: 'low', risk_reason: '仅影响样例流量',
  affected_assets: ['198.51.100.42'], business_impact: '只影响样例流量',
  expires_at: '2026-10-30T02:00:00Z', is_expired: false,
  rollback_steps: [{ step_id: 'RB-1', description: '撤销模拟规则', target: '198.51.100.42',
    expected_result: '恢复模拟配置', evidence_ids: ['EV-123'] }],
  validation_checks: [{ check_id: 'VC-1', description: '复查来源活动', target: '198.51.100.42',
    expected_result: '异常请求停止', query: { filters: { source_ip: '198.51.100.42' } }, evidence_ids: ['EV-123'] }],
  plan_version: planVersion,
} as const;
const idempotencyKey = '550e8400-e29b-41d4-a716-446655440000';
const detail = { ...item, plan_version: planVersion, approval: null, validation_result: null, simulation: [],
  pending_decision: null, available_actions: ['approve', 'reject'] };

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('响应方案读模型', () => {
  it('接受真实批准流程中新查询的验证证据和带偏移的时间戳', async () => {
    // The live ApiStore payload cites fresh validation evidence outside the plan's baseline.
    const validation = {
      validation_id: 'VR-6119694c2e22e29233e094f5', response_plan_id: 'RP-123',
      outcome: 'success', summary: 'Approved simulated actions match freshly queried target evidence.',
      checked_at: '2026-10-14T18:02:57.023023+08:00',
      evidence_ids: ['EV-fresh', 'EV-123'],
      time_from: '2026-09-21T18:05:24+08:00', time_to: '2026-09-21T18:35:24+08:00',
      checks: [{ check_id: 'VC-1', condition: { filters: { source_ip: action.target } },
        outcome: 'success', evidence_ids: ['EV-fresh', 'EV-123'], explanation: 'Fresh target evidence matched.' }],
    };
    const completed = { ...detail, incident_status: 'completed', decision_state: 'approved',
      available_actions: [], validation_result: validation };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(completed))));
    const parsed = await loadResponseDetail('RP-123');
    expect(parsed.validation_result).toEqual(validation);
    expect(parsed.evidence_ids).toEqual(['EV-123']);
    expect(Date.parse(parsed.validation_result!.checked_at)).toBe(Date.parse('2026-10-14T10:02:57.023023Z'));
    expect(responseDetailSchema.safeParse({ ...completed, validation_result: {
      ...validation, checks: [{ ...validation.checks[0], evidence_ids: ['EV-unlisted'] }],
    } }).success).toBe(false);
    expect(responseDetailSchema.safeParse({ ...completed, validation_result: {
      ...validation, checks: [{ ...validation.checks[0], check_id: 'VC-unknown' }],
    } }).success).toBe(false);
    expect(responseDetailSchema.safeParse({ ...completed, validation_result: {
      ...validation, checks: [{ ...validation.checks[0], outcome: 'unknown' }],
    } }).success).toBe(false);
    for (const checked_at of ['2026-10-14T18:02:57+99:00', '2026-02-30T18:02:57+08:00', 'not-a-date']) {
      expect(responseDetailSchema.safeParse({ ...completed, validation_result: { ...validation, checked_at } }).success).toBe(false);
    }
  });
  it('解析真实分页与详情，保留服务端的可用操作和提交中状态', () => {
    expect(responsePageSchema.parse({ items: [item], total: 1, page: 1, page_size: 20 }).items[0].response_plan_id).toBe('RP-123');
    expect(responsePageSchema.safeParse({ items: [{ ...item, plan_version: undefined }], total: 1, page: 1, page_size: 20 }).success).toBe(false);
    expect(responsePageSchema.parse({ items: [{ ...item, investigation_id: null }], total: 1, page: 1, page_size: 20 }).items[0].investigation_id).toBeNull();
    expect(responseDetailSchema.parse(detail).available_actions).toEqual(['approve', 'reject']);
    expect(responseDetailSchema.parse(detail).plan_version).toBe(planVersion);
    expect(responseDetailSchema.parse(detail).rollback_steps[0].step_id).toBe('RB-1');
    expect(responseDetailSchema.parse(detail).actions[0]).toMatchObject({
      action_id: null, type: null, parameters: null, expected_effect: null,
      rollback_ref: null, evidence_ids: null,
    });
    expect(responseDetailSchema.safeParse({ ...detail, plan_version: 'stale' }).success).toBe(false);
    expect(responseDetailSchema.safeParse({ ...detail, validation_checks: [{ ...item.validation_checks[0], check_id: '' }] }).success).toBe(false);
    expect(responseDetailSchema.parse({ ...detail, decision_state: 'submitting', pending_decision: 'approved', available_actions: [] }).pending_decision).toBe('approved');
  });
  it('拒绝不可信的状态、缺失模拟声明以及不一致方案引用', () => {
    expect(responsePageSchema.safeParse({ items: [{ ...item, decision_state: 'done' }], total: 1, page: 1, page_size: 20 }).success).toBe(false);
    expect(responseDetailSchema.safeParse({ ...detail, requires_approval: false }).success).toBe(false);
    expect(responseDetailSchema.safeParse({ ...detail, approval: {
      approval_id: 'AP-1', response_plan_id: 'RP-other', decision: 'approved', reason: 'ok', decided_by: 'owner', decided_at: '2026-09-29T03:00:00Z',
    } }).success).toBe(false);
  });
  it('拒绝不完整、越权或目标不匹配的模拟动作', () => {
    const invalidActions = [
      { ...action, target: 'not-an-ip' },
      { ...action, risk: '  ' },
      { ...action, verification_query: { filters: { source_ip: '198.51.100.99' } } },
      { ...action, verification_query: { filters: { source_ip: action.target }, shell: 'whoami' } },
      { ...action, verification_query: { filters: { source_ip: action.target }, limit: 0 } },
      { ...action, verification_query: { filters: { url: 'https://example.test' } } },
      { ...action, verification_query: { filters: { source_ip: action.target }, time_from: '2026-09-29T02:00:00Z' } },
      { ...action, command: 'iptables -A INPUT -j DROP' },
    ];
    for (const invalid of invalidActions) {
      expect(responseDetailSchema.safeParse({ ...detail, actions: [invalid] }).success).toBe(false);
    }
  });
  it('保留逐动作模拟与验证的可追溯结果，并拒绝跨方案引用', () => {
    const tracedAction = {
      ...action, action_id: 'ACT-1', type: 'block_ip_simulated',
      parameters: { source_ip: action.target }, expected_effect: '异常请求不再出现',
      rollback_ref: 'RB-1', evidence_ids: ['EV-123'],
    };
    const simulationExecution = {
      simulation_id: 'SIM-1', response_plan_id: 'RP-123', plan_version: planVersion,
      status: 'completed', started_at: '2026-09-29T02:10:00Z', finished_at: '2026-09-29T02:10:01Z',
      action_results: [{ action_id: 'ACT-1', outcome: 'success', description: '模拟完成',
        started_at: '2026-09-29T02:10:00Z', finished_at: '2026-09-29T02:10:01Z' }], error: null,
    };
    const validation = {
      validation_id: 'VAL-1', response_plan_id: 'RP-123', outcome: 'success', summary: '检查通过',
      checked_at: '2026-09-29T02:12:00Z', evidence_ids: ['EV-123'],
      time_from: '2026-09-29T02:10:00Z', time_to: '2026-09-29T02:12:00Z',
      checks: [{ check_id: 'VC-1', condition: { filters: { source_ip: action.target } },
        outcome: 'success', evidence_ids: ['EV-123'], explanation: '查询结果符合条件' }],
    };
    const tracedDetail = { ...detail, actions: [tracedAction], simulation_execution: simulationExecution,
      validation_result: validation };
    const parsed = responseDetailSchema.parse(tracedDetail);
    expect(parsed.actions[0].action_id).toBe('ACT-1');
    expect(parsed.simulation_execution?.action_results[0].action_id).toBe('ACT-1');
    expect(parsed.validation_result?.checks[0].check_id).toBe('VC-1');
    expect(responseDetailSchema.parse({ ...tracedDetail, validation_result: {
      validation_id: validation.validation_id, response_plan_id: validation.response_plan_id,
      outcome: validation.outcome, summary: validation.summary,
      checked_at: validation.checked_at, evidence_ids: validation.evidence_ids,
    } }).validation_result).toMatchObject({ time_from: null, time_to: null, checks: [] });
    expect(responseDetailSchema.safeParse({ ...tracedDetail, simulation_execution: {
      ...simulationExecution, response_plan_id: 'RP-other',
    } }).success).toBe(false);
    expect(responseDetailSchema.safeParse({ ...tracedDetail, simulation_execution: {
      ...simulationExecution, action_results: [{ ...simulationExecution.action_results[0], action_id: 'ACT-other' }],
    } }).success).toBe(false);
    expect(responseDetailSchema.safeParse({ ...tracedDetail, actions: [{ ...tracedAction, evidence_ids: ['EV-other'] }] }).success).toBe(false);
    expect(responseDetailSchema.safeParse({ ...tracedDetail, actions: [{ ...tracedAction,
      parameters: { source_ip: '198.51.100.99' },
    }] }).success).toBe(false);
    expect(responseDetailSchema.parse({ ...detail, actions: [{ ...action, action_id: null,
      type: null, parameters: null, expected_effect: null, rollback_ref: null, evidence_ids: null,
    }] }).actions[0].action_id).toBeNull();
  });
  it('恢复 URL 筛选；无效参数回退；构建允许的查询字段', () => {
    expect(readResponseFilters(new URLSearchParams('page=2&page_size=50&decision_state=pending'))).toEqual({ page: 2, pageSize: 50, decisionState: 'pending' });
    expect(readResponseFilters(new URLSearchParams('page=-1&page_size=999&decision_state=submitting'))).toEqual({ page: 1, pageSize: 20, decisionState: undefined });
    expect(buildResponseQuery({ page: 2, pageSize: 50, decisionState: 'approved' })).toBe('page=2&page_size=50&decision_state=approved');
  });
});

describe('同源响应请求', () => {
  it('过期续办只发送一次且带方案版本和幂等键', async () => {
    const accepted = {
      response_plan_id: 'RP-123', investigation_id: 'IV-123', incident_id: 'IN-123',
      trace_id: 'TRACE-renew', status: 'accepted', stream_url: '/api/v1/investigations/IV-123/stream',
    };
    const mockedFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(accepted), { status: 202 }));
    vi.stubGlobal('fetch', mockedFetch);
    expect(await submitPlanRenewal('RP-123', planVersion, idempotencyKey)).toEqual(accepted);
    expect(mockedFetch).toHaveBeenCalledTimes(1);
    expect(mockedFetch.mock.calls[0][0]).toBe('/api/v1/response-plans/RP-123/renew');
    expect(JSON.parse(mockedFetch.mock.calls[0][1].body)).toEqual({ plan_version: planVersion });
    expect(mockedFetch.mock.calls[0][1].headers['Idempotency-Key']).toBe(idempotencyKey);
  });
  it('读取列表时检查页码，不把服务器错误伪装为空队列', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ items: [item], total: 1, page: 2, page_size: 20 })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'OFFLINE', message: '服务不可用', trace_id: 'TRACE-1' } }), { status: 503 })));
    await expect(loadResponsePlans({ page: 1, pageSize: 20 })).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
    await expect(loadResponsePlans({ page: 1, pageSize: 20 })).rejects.toMatchObject({ code: 'OFFLINE', traceId: 'TRACE-1', status: 503 });
  });
  it('详情必须属于请求的方案，不接受其他方案的结果', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...detail, response_plan_id: 'RP-other' }))));
    await expect(loadResponseDetail('RP-123')).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });
  it('审批只发送一次、修剪理由，并只将 202 解释为已受理', async () => {
    const accepted = { response_plan_id: 'RP-123', investigation_id: 'IV-123', incident_id: 'IN-123', trace_id: 'TRACE-2', decision: 'approved', status: 'accepted' };
    const mockedFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(accepted), { status: 202 }));
    vi.stubGlobal('fetch', mockedFetch);
    expect(await submitResponseDecision('RP-123', 'approve', {
      plan_version: planVersion, reason: '  已核对证据  ',
    }, idempotencyKey)).toEqual(accepted);
    expect(mockedFetch).toHaveBeenCalledTimes(1);
    expect(mockedFetch.mock.calls[0][0]).toBe('/api/v1/response-plans/RP-123/approve');
    expect(JSON.parse(mockedFetch.mock.calls[0][1].body)).toEqual({ plan_version: planVersion, reason: '已核对证据' });
    expect(mockedFetch.mock.calls[0][1].headers['Idempotency-Key']).toBe(idempotencyKey);
  });
  it('空白理由不发送，409 不自动重发并保留冲突状态', async () => {
    const mockedFetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: 'ALREADY_DECIDED', message: '已审批', trace_id: 'TRACE-3' } }), { status: 409 }));
    vi.stubGlobal('fetch', mockedFetch);
    await expect(submitResponseDecision('RP-123', 'reject', {
      plan_version: planVersion, reason: ' ',
    }, idempotencyKey)).rejects.toMatchObject({ code: 'INVALID_REASON' });
    expect(mockedFetch).not.toHaveBeenCalled();
    await expect(submitResponseDecision('RP-123', 'reject', {
      plan_version: planVersion, reason: '证据不足',
    }, idempotencyKey)).rejects.toMatchObject({ code: 'ALREADY_DECIDED', status: 409 });
    expect(mockedFetch).toHaveBeenCalledTimes(1);
  });
});
