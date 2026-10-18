'use client';

import { useRef, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Button, Input, Modal } from 'antd';
import { AlertCircle, LoaderCircle, ShieldCheck } from 'lucide-react';
import { severityLabels, statusLabels } from '../alerts/alertsContract';
import {
  buildResponseQuery, loadResponseDetail, readResponseFilters, responseDetailRefetchInterval, ResponsePlanRequestError,
  submitPlanRenewal, submitResponseDecision, type ResponsePlanDetail,
} from './responseContract';
import { loadDemoSession, startDemoSession } from './sessionContract';
import styles from './ResponseDetail.module.css';

const actionNames = {
  block_ip_simulated: '模拟限制来源 IP',
  isolate_host_simulated: '模拟隔离主机',
  disable_account_simulated: '模拟停用账号',
} as const;
const outcomeNames = {
  success: '验证成功', failure: '验证失败', insufficient_evidence: '证据不足',
} as const;
const decisionNames = {
  pending: '待处理', submitting: '提交中', approved: '已批准', rejected: '已拒绝',
} as const;
const riskNames = { low: '低', medium: '中', high: '高', critical: '严重' } as const;
const executionStatusNames = { pending: '待执行', running: '执行中', completed: '已完成', failed: '执行失败' } as const;
const actionOutcomeNames = { success: '模拟成功', failure: '模拟失败', skipped: '已跳过' } as const;
const dateFormatter = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
});

function Time({ value }: { value: string }) {
  return <time dateTime={value} title={value}>{dateFormatter.format(new Date(value))}</time>;
}

function EvidenceLinks({ ids, incidentId }: { ids: string[]; incidentId: string }) {
  return <span className={styles.evidenceLinks}>{ids.map((id) => <Link
    key={id} href={`/incidents/${encodeURIComponent(incidentId)}`}>{id}</Link>)}</span>;
}

function PlanSections({ detail }: { detail: ResponsePlanDetail }) {
  return <div className={styles.mainColumn}>
    <section className={styles.panel} aria-labelledby="response-overview-heading">
      <h2 id="response-overview-heading">方案概况</h2>
      <dl className={styles.facts}>
        <div><dt>响应方案</dt><dd><code>{detail.response_plan_id}</code></dd></div>
        <div><dt>方案版本</dt><dd><code title={detail.plan_version}>{detail.plan_version.slice(0, 12)}</code></dd></div>
        <div><dt>关联案件</dt><dd><Link href={`/incidents/${encodeURIComponent(detail.incident_id)}`}>{detail.incident_id}</Link></dd></div>
        <div><dt>调查编号</dt><dd>{detail.investigation_id ?? '暂无'}</dd></div>
        <div><dt>告警</dt><dd><Link href={`/alerts/${encodeURIComponent(detail.alert_id)}`}>{detail.alert_title}</Link></dd></div>
        <div><dt>严重性 / 案件状态</dt><dd>{severityLabels[detail.severity]} · {statusLabels[detail.incident_status]}</dd></div>
        <div><dt>生成时间（UTC+8）</dt><dd><Time value={detail.created_at} /></dd></div>
        <div><dt>执行方式</dt><dd>{detail.execution_mode === 'simulation' ? '安全模拟' : '未知'}</dd></div>
        <div><dt>方案风险</dt><dd>{detail.risk_level ? `${riskNames[detail.risk_level]}风险` : '未评估'}{detail.risk_reason && <span className={styles.factDetail}>{detail.risk_reason}</span>}</dd></div>
        <div><dt>影响资产</dt><dd>{detail.affected_assets.length ? detail.affected_assets.join('、') : '未提供'}</dd></div>
        <div><dt>业务影响</dt><dd>{detail.business_impact ?? '未提供'}</dd></div>
        <div><dt>审批有效期（UTC+8）</dt><dd>{detail.expires_at ? <Time value={detail.expires_at} /> : '未设置'}{detail.is_expired && <span className={styles.expired}> · 已过期</span>}</dd></div>
      </dl>
    </section>

    <section className={styles.panel} aria-labelledby="response-rollback-heading">
      <h2 id="response-rollback-heading">回滚计划</h2>
      {detail.rollback_steps.length ? <ol className={styles.actions}>{detail.rollback_steps.map((step) => <li key={step.step_id}>
        <div className={styles.actionHeading}><h3>{step.description}</h3><code>{step.step_id}</code></div>
        <dl className={styles.actionFacts}>
          <div><dt>目标</dt><dd>{step.target}</dd></div>
          <div><dt>预期结果</dt><dd>{step.expected_result}</dd></div>
          <div><dt>依据证据</dt><dd><EvidenceLinks ids={step.evidence_ids} incidentId={detail.incident_id} /></dd></div>
        </dl>
      </li>)}</ol> : <p className={styles.intro}>未提供独立回滚步骤，请核对各模拟动作中的回滚说明。</p>}
    </section>

    <section className={styles.panel} aria-labelledby="response-checks-heading">
      <h2 id="response-checks-heading">验证条件</h2>
      {detail.validation_checks.length ? <ol className={styles.actions}>{detail.validation_checks.map((check) => <li key={check.check_id}>
        <div className={styles.actionHeading}><h3>{check.description}</h3><code>{check.check_id}</code></div>
        <dl className={styles.actionFacts}>
          <div><dt>目标</dt><dd>{check.target}</dd></div>
          <div><dt>预期结果</dt><dd>{check.expected_result}</dd></div>
          <div><dt>依据证据</dt><dd><EvidenceLinks ids={check.evidence_ids} incidentId={detail.incident_id} /></dd></div>
        </dl>
        <details className={styles.query}><summary>查看验证查询范围</summary><pre>{JSON.stringify(check.query, null, 2)}</pre></details>
      </li>)}</ol> : <p className={styles.intro}>未提供独立验证条件；批准后仍需以服务端实际验证结果为准。</p>}
    </section>

    <section className={styles.panel} aria-labelledby="response-actions-heading">
      <h2 id="response-actions-heading">拟模拟的动作</h2>
      <p className={styles.intro}>以下信息来自响应方案。页面不会执行真实封禁、隔离或账号停用。</p>
      {detail.actions.some((action) => !action.action_id) && <p className={styles.intro}>历史方案未提供完整动作编号，无法将旧模拟记录逐项对应到动作。</p>}
      <ol className={styles.actions}>{detail.actions.map((action, index) => <li key={action.action_id ?? `${action.action}-${action.target}-${index}`}>
        <div className={styles.actionHeading}><h3>{actionNames[action.action]}</h3><code>{action.action_id ?? action.target}</code></div>
        <dl className={styles.actionFacts}>
          {action.action_id && <div><dt>动作编号</dt><dd><code>{action.action_id}</code></dd></div>}
          <div><dt>目标</dt><dd>{action.target}</dd></div>
          <div><dt>模拟内容</dt><dd>{action.preview}</dd></div>
          {action.expected_effect && <div><dt>预期效果</dt><dd>{action.expected_effect}</dd></div>}
          <div><dt>预计影响</dt><dd>{action.impact}</dd></div>
          <div><dt>风险</dt><dd>{action.risk}</dd></div>
          <div><dt>模拟回滚</dt><dd>{action.rollback}</dd></div>
          {action.rollback_ref && <div><dt>回滚关联</dt><dd>关联回滚步骤：{action.rollback_ref}</dd></div>}
          {action.evidence_ids && <div><dt>依据证据</dt><dd><EvidenceLinks ids={action.evidence_ids} incidentId={detail.incident_id} /></dd></div>}
        </dl>
        {action.parameters && <details className={styles.query}><summary>查看动作参数</summary><pre>{JSON.stringify(action.parameters, null, 2)}</pre></details>}
        <details className={styles.query}><summary>查看验证查询范围</summary><pre>{JSON.stringify(action.verification_query, null, 2)}</pre></details>
      </li>)}</ol>
    </section>

    <section className={styles.panel} aria-labelledby="response-evidence-heading">
      <h2 id="response-evidence-heading">关联证据</h2>
      <p className={styles.intro}>请到案件详情核对证据，再决定是否批准。</p>
      <ul className={styles.evidence}>{detail.evidence_ids.map((id) => <li key={id}><EvidenceLinks ids={[id]} incidentId={detail.incident_id} /></li>)}</ul>
      <Link href={`/incidents/${encodeURIComponent(detail.incident_id)}`}>查看案件证据</Link>
    </section>

    <section className={styles.panel} aria-labelledby="response-progress-heading">
      <h2 id="response-progress-heading">模拟与验证结果</h2>
      {detail.simulation_execution ? <div className={styles.execution}>
        <h3>逐动作模拟结果</h3>
        <p>执行编号：<code>{detail.simulation_execution.simulation_id}</code> · {executionStatusNames[detail.simulation_execution.status]}</p>
        {detail.simulation_execution.started_at && <p>开始时间：<Time value={detail.simulation_execution.started_at} /></p>}
        {detail.simulation_execution.finished_at && <p>结束时间：<Time value={detail.simulation_execution.finished_at} /></p>}
        {detail.simulation_execution.error && <p role="alert">执行错误：{detail.simulation_execution.error}</p>}
        {detail.simulation_execution.action_results.length ? <ul className={styles.results}>
          {detail.simulation_execution.action_results.map((result) => {
            const action = detail.actions.find((item) => item.action_id === result.action_id);
            return <li key={result.action_id}>
              <strong>{action ? actionNames[action.action] : '未知动作'} · {result.action_id}</strong>
              <span>{actionOutcomeNames[result.outcome]} · {result.description}</span>
              {action && <small>目标：{action.target}{action.rollback_ref ? ` · 回滚：${action.rollback_ref}` : ''}</small>}
            </li>;
          })}</ul> : <p className={styles.intro}>尚无逐动作模拟结果。</p>}
      </div> : detail.simulation.length === 0 ? <p className={styles.intro}>尚无模拟执行结果。</p>
        : <ul className={styles.results}>{detail.simulation.map((result) => <li key={result.execution_id}>
          <strong>{actionNames[result.action]} · {result.target}</strong>
          <span>{result.status} · {result.outcome}</span>
          <small>执行编号：{result.execution_id} · 历史记录未提供动作编号</small>
        </li>)}</ul>}
      {detail.validation_result ? <div className={styles.validation}>
        <h3>{outcomeNames[detail.validation_result.outcome]}</h3>
        <p>{detail.validation_result.summary}</p>
        <p>验证时间：<Time value={detail.validation_result.checked_at} /></p>
        {detail.validation_result.time_from && detail.validation_result.time_to ? <p>
          验证时间窗（UTC+8）：<Time value={detail.validation_result.time_from} /> 至 <Time value={detail.validation_result.time_to} />
        </p> : <p>验证时间窗未记录。</p>}
        {detail.validation_result.checks?.length ? <ul className={styles.results}>
          {detail.validation_result.checks.map((check) => <li key={check.check_id}>
            <strong>{check.check_id} · {outcomeNames[check.outcome]}</strong>
            <span>{check.explanation}</span>
            <small>关联证据：<EvidenceLinks ids={check.evidence_ids} incidentId={detail.incident_id} /></small>
            <details className={styles.query}><summary>查看实际验证条件</summary><pre>{JSON.stringify(check.condition, null, 2)}</pre></details>
          </li>)}</ul> : <p>未记录逐项验证条件。</p>}
      </div> : <p className={styles.intro}>尚无效果验证结论。审批受理不代表模拟或验证成功。</p>}
    </section>
  </div>;
}

export default function ResponseDetail({ id }: { id: string }) {
  const params = useSearchParams();
  const from = params.get('from');
  const backHref = from === null ? '/responses' : `/responses?${buildResponseQuery(readResponseFilters(new URLSearchParams(from)))}`;
  const query = useQuery({
    queryKey: ['response-plan-detail', id], queryFn: ({ signal }) => loadResponseDetail(id, signal),
    retry: false, staleTime: 0,
    refetchInterval: (current) => responseDetailRefetchInterval(current.state.data),
  });
  const sessionQuery = useQuery({
    queryKey: ['demo-session'], queryFn: loadDemoSession,
    retry: false, staleTime: 0, refetchInterval: 60_000,
  });
  const [reason, setReason] = useState('');
  const [sessionStarting, setSessionStarting] = useState(false);
  const [sessionError, setSessionError] = useState<ResponsePlanRequestError | null>(null);
  const [modalAction, setModalAction] = useState<'approve' | 'reject' | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submissionLocked, setSubmissionLocked] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<ResponsePlanRequestError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [renewing, setRenewing] = useState(false);
  const [renewalLocked, setRenewalLocked] = useState(false);
  const [renewalError, setRenewalError] = useState<ResponsePlanRequestError | null>(null);
  const [renewalIncidentId, setRenewalIncidentId] = useState<string | null>(null);
  const inFlight = useRef(false);
  const detail = query.data;
  const session = sessionQuery.data;
  const loadError = query.error instanceof ResponsePlanRequestError ? query.error : null;
  const missingReviewDetails = detail ? [
    !detail.risk_level || !detail.risk_reason?.trim() ? '风险说明' : null,
    !detail.business_impact?.trim() || detail.affected_assets.length === 0 ? '业务影响' : null,
    !detail.expires_at ? '有效期' : null,
    detail.rollback_steps.length === 0 ? '回滚计划' : null,
    detail.validation_checks.length === 0 ? '验证条件' : null,
    detail.actions.some((action) => !action.action_id || !action.type || !action.parameters
      || !action.expected_effect || !action.rollback_ref || !action.evidence_ids?.length)
      ? '动作追溯信息（编号、参数、预期效果、回滚关联和证据引用）' : null,
  ].filter((value): value is string => value !== null) : [];
  const canChoose = detail?.decision_state === 'pending' && detail.is_current && !detail.is_expired
    && Boolean(session) && !sessionQuery.isFetching && !sessionQuery.isError
    && !query.isFetching && !query.isError && !submissionLocked;

  async function enableDemoSession() {
    if (sessionStarting) return;
    setSessionStarting(true);
    setSessionError(null);
    try {
      await startDemoSession();
      const refreshed = await sessionQuery.refetch();
      if (!refreshed.data) throw new ResponsePlanRequestError('SESSION_REQUIRED', '会话未建立，请重试。');
    } catch (cause) {
      setSessionError(cause instanceof ResponsePlanRequestError ? cause
        : new ResponsePlanRequestError('SESSION_ERROR', '无法启用本地演示账户，请重试。'));
    } finally {
      setSessionStarting(false);
    }
  }

  function choose(action: 'approve' | 'reject') {
    setFormError(null);
    setSubmitError(null);
    if (!canChoose || !detail?.available_actions.includes(action) || !session?.allowed_actions.includes(action)) return;
    if (!reason.trim()) {
      setFormError('请填写决定理由。批准与拒绝均须说明依据。');
      return;
    }
    if (reason.trim().length > 2000) {
      setFormError('决定理由最多 2000 字。');
      return;
    }
    setModalAction(action);
  }

  async function confirm() {
    if (!detail || !modalAction || inFlight.current || !canChoose || !detail.available_actions.includes(modalAction)) return;
    const chosen = modalAction;
    inFlight.current = true;
    setSubmitting(true);
    setSubmitError(null);
    setNotice(null);
    try {
      const freshSession = await sessionQuery.refetch();
      if (!freshSession.data?.allowed_actions.includes(chosen)) {
        throw new ResponsePlanRequestError('SESSION_REQUIRED', '演示会话已失效，请重新启用后核对方案。', undefined, 401);
      }
      await submitResponseDecision(detail.response_plan_id, chosen, {
        plan_version: detail.plan_version, reason,
      }, crypto.randomUUID());
      setSubmissionLocked(true);
      setModalAction(null);
      setNotice('审批请求已受理，正在读取服务端最新状态；这不代表方案已批准或模拟已完成。');
      await query.refetch();
    } catch (cause) {
      const error = cause instanceof ResponsePlanRequestError ? cause
        : new ResponsePlanRequestError('UNKNOWN_ERROR', '提交结果未知。请刷新方案详情确认，勿直接重复提交。');
      setSubmitError(error);
      setModalAction(null);
      if (error.status === 401 || error.status === 403) await sessionQuery.refetch();
      if (error.status === 409 || error.status === 410 || !error.status || error.status >= 500) {
        setSubmissionLocked(true);
        await query.refetch();
      }
      inFlight.current = false;
    } finally {
      setSubmitting(false);
    }
  }

  async function renewExpiredPlan() {
    if (!detail || !detail.is_expired || !detail.is_current || detail.decision_state !== 'pending'
      || detail.incident_status !== 'awaiting_approval' || renewing || renewalLocked || inFlight.current) return;
    inFlight.current = true;
    setRenewing(true);
    setRenewalError(null);
    try {
      const freshSession = await sessionQuery.refetch();
      if (!freshSession.data) {
        throw new ResponsePlanRequestError('SESSION_REQUIRED', '演示会话已失效，请重新启用后核对方案。', undefined, 401);
      }
      const accepted = await submitPlanRenewal(detail.response_plan_id, detail.plan_version, crypto.randomUUID());
      setRenewalLocked(true);
      setRenewalIncidentId(accepted.incident_id);
      setNotice('续办请求已受理，正在基于已核验的证据重新生成方案；这不代表新方案已获批准。');
      await query.refetch();
    } catch (cause) {
      const error = cause instanceof ResponsePlanRequestError ? cause
        : new ResponsePlanRequestError('UNKNOWN_ERROR', '续办结果未知。请刷新方案详情确认，勿直接重复提交。');
      setRenewalError(error);
      if (error.status === 401 || error.status === 403) await sessionQuery.refetch();
      if (error.status === 409 || error.status === 410 || !error.status || error.status >= 500) {
        setRenewalLocked(true);
        await query.refetch();
      }
    } finally {
      inFlight.current = false;
      setRenewing(false);
    }
  }

  return <div className={styles.page}>
    <Link className={styles.backLink} href={backHref}>返回响应队列</Link>
    {!detail && query.isPending ? <div className={styles.state} role="status"><LoaderCircle size={26} aria-hidden="true" /><p>正在加载响应方案…</p></div>
      : !detail && query.isError ? <div className={styles.state} role="alert">
        <AlertCircle size={26} aria-hidden="true" />
        <h1>{loadError?.status === 404 ? '响应方案不存在' : '响应方案加载失败'}</h1>
        <p>{loadError?.message ?? '请求失败，请重试。'}</p>
        {loadError && <p>错误代码：{loadError.code}</p>}
        {loadError?.traceId && <p>Trace ID：<code>{loadError.traceId}</code></p>}
        <Button autoInsertSpace={false} onClick={() => { void query.refetch(); }}>重试</Button>
      </div> : detail ? <>
        <header className={styles.header}>
          <div><p className={styles.eyebrow}>人工响应审查</p><h1>{detail.summary}</h1>
            <p className={styles.identifier}>{detail.response_plan_id} · 仅模拟处置</p></div>
          <span className={styles.status} data-state={detail.decision_state}>{decisionNames[detail.decision_state]}</span>
        </header>
        {query.isError && <div className={styles.message} role="alert">
          更新失败，当前显示上次成功读取的方案。{loadError?.message ?? ''}
          {loadError?.traceId && <> Trace ID：<code>{loadError.traceId}</code></>}
          <Button autoInsertSpace={false} onClick={() => { void query.refetch(); }}>重试</Button>
        </div>}
        {notice && <div className={styles.message} role="status"><ShieldCheck size={18} aria-hidden="true" />{notice}</div>}
        {submitError && <div className={styles.message} role="alert">
          {submitError.status === 409 ? '方案已决定或状态已变更。已重新读取服务端记录。' : submitError.message}
          <span>错误代码：{submitError.code}</span>
          {submitError.traceId && <span>Trace ID：<code>{submitError.traceId}</code></span>}
        </div>}
        <div className={styles.columns}>
          <PlanSections detail={detail} />
          <aside className={styles.decision} aria-labelledby="response-decision-heading">
            <div className={styles.decisionHeader}><h2 id="response-decision-heading">人工决定</h2>
              <span className={styles.status} data-state={detail.decision_state}>{decisionNames[detail.decision_state]}</span></div>
            <p className={styles.decisionIntro}>本方案仅执行模拟动作。请先核对动作、影响、回滚说明和关联证据。</p>
            {session ? <p className={styles.identityNote}>当前审批账户：<strong>{session.actor_id}</strong> · 本地演示会话</p>
              : sessionQuery.isPending ? <p className={styles.decisionNote}>正在校验审批会话…</p>
              : sessionQuery.isError ? <p className={styles.decisionNote} role="alert">会话服务不可用，请稍后重试。
                <Button autoInsertSpace={false} onClick={() => { void sessionQuery.refetch(); }}>重试会话检查</Button></p>
              : <p className={styles.decisionNote}>审批前请启用本地演示账户。
                <Button autoInsertSpace={false} loading={sessionStarting} onClick={() => { void enableDemoSession(); }}>启用本地演示账户</Button></p>}
            {sessionError && <p className={styles.formError} role="alert">{sessionError.message}</p>}
            {!detail.is_current && <p className={styles.decisionNote}>这是历史方案，不能再提交决定。</p>}
            {detail.is_current && detail.decision_state === 'pending' && !detail.is_expired
              && detail.available_actions.length === 1 && detail.available_actions[0] === 'reject'
              && missingReviewDetails.length > 0 && <p className={styles.decisionNote} role="alert">
                此方案缺少{missingReviewDetails.join('、')}，当前仅可拒绝。请核对后填写拒绝理由。
              </p>}
            {detail.is_expired && <p className={styles.decisionNote} role="alert">方案已过期，不能提交决定。请重新获取有效方案。</p>}
            {detail.is_expired && detail.is_current && detail.decision_state === 'pending'
              && detail.incident_status === 'awaiting_approval' && !renewalLocked && <Button
                autoInsertSpace={false} loading={renewing}
                disabled={!session || sessionQuery.isFetching || sessionQuery.isError || query.isFetching || query.isError}
                onClick={() => { void renewExpiredPlan(); }}>重新生成方案</Button>}
            {renewalError && <p className={styles.formError} role="alert">
              {renewalError.message} 错误代码：{renewalError.code}
              {renewalError.traceId && <> Trace ID：<code>{renewalError.traceId}</code></>}
            </p>}
            {renewalIncidentId && <p className={styles.decisionNote}><Link href={`/incidents/${encodeURIComponent(renewalIncidentId)}`}>查看续办调查</Link></p>}
            {detail.pending_decision && <p className={styles.decisionNote}>
              已提交{detail.pending_decision === 'approved' ? '批准' : '拒绝'}请求，等待服务端处理。
            </p>}
            {detail.approval ? <div className={styles.approval}>
              <h3>已记录的审批</h3>
              <dl><div><dt>决定</dt><dd>{detail.approval.decision === 'approved' ? '已批准' : '已拒绝'}</dd></div>
                <div><dt>审批人</dt><dd>{detail.approval.decided_by}</dd></div>
                <div><dt>决定时间</dt><dd><Time value={detail.approval.decided_at} /></dd></div>
                <div><dt>理由</dt><dd>{detail.approval.reason}</dd></div></dl>
            </div> : detail.available_actions.length > 0 && detail.decision_state === 'pending' && detail.is_current && !detail.is_expired && !submissionLocked ? <>
              <label className={styles.field} htmlFor="response-reason">决定理由
                <Input.TextArea id="response-reason" aria-label="决定理由" value={reason} maxLength={2000}
                  onChange={(event) => setReason(event.target.value)} rows={5}
                  placeholder="写明证据、影响与判断依据；批准和拒绝都必须填写。" />
              </label>
              {formError && <p className={styles.formError} role="alert">{formError}</p>}
              <div className={styles.buttons}>
                {detail.available_actions.includes('approve') && <Button type="primary" disabled={!canChoose || !session?.allowed_actions.includes('approve')} onClick={() => choose('approve')}>批准方案</Button>}
                {detail.available_actions.includes('reject') && <Button danger disabled={!canChoose || !session?.allowed_actions.includes('reject')} onClick={() => choose('reject')}>拒绝方案</Button>}
              </div>
            </> : <p className={styles.decisionNote}>当前没有可提交的人工决定。请以服务端状态为准。</p>}
            <Button className={styles.refresh} autoInsertSpace={false} loading={query.isFetching} onClick={() => { void query.refetch(); }}>刷新服务端状态</Button>
          </aside>
        </div>
        <Modal open={modalAction !== null} title={modalAction === 'approve' ? '确认批准' : '确认拒绝'}
          onCancel={() => { if (!submitting) setModalAction(null); }}
          onOk={() => { void confirm(); }} confirmLoading={submitting}
          okText={modalAction === 'approve' ? '确认提交批准' : '确认提交拒绝'}
          okButtonProps={{ danger: modalAction === 'reject' }} cancelText="返回核对" closable={!submitting}
          mask={{ closable: !submitting }}>
          <p>即将提交本方案的人工决定。服务端受理后仍需等待审批记录、模拟和验证结果。</p>
          <dl className={styles.confirmFacts}>
            <div><dt>方案</dt><dd><code>{detail.response_plan_id}</code></dd></div>
            <div><dt>决定</dt><dd>{modalAction === 'approve' ? '批准' : '拒绝'}</dd></div>
            <div><dt>审批账户</dt><dd>{session?.actor_id ?? '会话已失效'}</dd></div>
            <div><dt>方案风险</dt><dd>{detail.risk_level ? `${riskNames[detail.risk_level]}风险` : '未评估'}</dd></div>
            <div><dt>有效期</dt><dd>{detail.expires_at ? <Time value={detail.expires_at} /> : '未设置'}</dd></div>
            <div><dt>理由</dt><dd>{reason.trim()}</dd></div>
          </dl>
        </Modal>
      </> : null}
  </div>;
}
