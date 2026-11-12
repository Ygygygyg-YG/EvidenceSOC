'use client';

import { useCallback, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { Button, Drawer } from 'antd';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { ArrowUpRight, FileSearch, ShieldAlert } from 'lucide-react';
import { severityLabels, statusLabels } from '../alerts/alertsContract';
import type { IncidentSummary } from './incidentContract';
import type { AttackGraphData } from './investigationSnapshotContract';
import { EvidenceDetailRequestError, loadEvidenceDetail } from './evidenceDetailContract';
import { EvidencePageRequestError, loadEvidencePage } from './evidencePageContract';
import { loadDemoSession, startDemoSession } from '../responses/sessionContract';
import { StepMetadata, StepTime, stepDetails, type GraphStep } from './attackStepDetails';
import StepSphere from './StepSphere';
import styles from './IncidentDetail.module.css';

const AttackGraph = dynamic(() => import('./AttackGraph'), { ssr: false,
  loading: () => <div className={styles.graphLoading} role="status">正在加载攻击链图谱…</div> });

type AttackStep = IncidentSummary['attack_steps'][number];
type AgentRun = IncidentSummary['runs'][number];
type EvidenceItem = IncidentSummary['evidence'][number];
const evidencePageSize = 20;

function subscribeMobile(callback: () => void) {
  const query = window.matchMedia('(max-width: 767px)');
  query.addEventListener('change', callback);
  return () => query.removeEventListener('change', callback);
}

function getMobile() { return window.matchMedia('(max-width: 767px)').matches; }

const dateFormatter = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
});

function formatTime(value: string | null | undefined) {
  return value ? dateFormatter.format(new Date(value)) : '未提供';
}

const roleSteps = [
  { key: 'triage', label: '分诊' },
  { key: 'collect', label: '证据收集' },
  { key: 'analyze', label: '威胁分析' },
  { key: 'reconstruct', label: '攻击链重构' },
  { key: 'respond', label: '响应决策' },
  { key: 'validate', label: '效果验证' },
] as const;

const runLabels: Record<AgentRun['status'], string> = {
  pending: '待运行', running: '运行中', completed: '已完成', failed: '失败',
};

function ContextPanel({ incident, evidenceItems, evidenceTotal, showEvidenceOverview }: {
  incident: IncidentSummary; evidenceItems: EvidenceItem[]; evidenceTotal: number | null;
  showEvidenceOverview: (trigger: HTMLButtonElement) => void;
}) {
  const primary = incident.alerts[0];
  return (
    <section className={styles.panel} aria-labelledby="incident-context-heading">
      <div className={styles.sectionHeading}><h2 id="incident-context-heading">调查上下文</h2></div>
      <dl className={styles.contextFacts}>
        <div><dt>案件编号</dt><dd className={styles.identifier}>{incident.incident_id}</dd></div>
        <div><dt>当前状态</dt><dd><span className={styles.statusBadge}>{statusLabels[incident.status]}</span></dd></div>
        <div><dt>关联告警</dt><dd><Link href={`/alerts/${encodeURIComponent(incident.alert_id)}`}>{primary?.title ?? incident.alert_id}</Link>{primary && <span className={styles.listMeta}>{severityLabels[primary.severity]} · {primary.alert_id}</span>}</dd></div>
        <div><dt>调查编号</dt><dd className={styles.identifier}>{incident.investigation_id ?? '尚未创建'}</dd></div>
        <div><dt>创建时间（UTC+8）</dt><dd>{formatTime(incident.created_at)}</dd></div>
        <div><dt>观察到的源 IP</dt><dd className={styles.identifier}>{incident.origin?.observed_source_ip ?? '未知'}</dd></div>
        <div><dt>入口主机 / 服务</dt><dd>{incident.origin?.entry_host ?? '未知'} / {incident.origin?.entry_service ?? '未知'}</dd></div>
        <div><dt>首次观察时间（UTC+8）</dt><dd>{formatTime(incident.origin?.first_seen_at)}</dd></div>
        <div><dt>攻击类型候选</dt><dd>{incident.classification?.primary_type ?? '未知'}</dd></div>
        <div><dt>ATT&CK 技术</dt><dd>{incident.classification?.technique_ids.join('、') || '未提供'}</dd></div>
        <div><dt>分类输出置信度</dt><dd>{incident.classification ? `${Math.round(incident.classification.confidence * 100)}%` : '未提供'}<span className={styles.listMeta}>后端分类输出；计算依据未提供</span></dd></div>
        <div><dt>证据总数</dt><dd>{evidenceTotal === null ? `当前快照 ${incident.evidence.length} 条（总数未核实）` : `${evidenceTotal} 条`}</dd></div>
        {incident.trace_id && <div><dt>Trace ID</dt><dd className={styles.identifier}>{incident.trace_id}</dd></div>}
      </dl>
      {incident.fallback_used && <p className={styles.note}>本次调查使用了规则回退结果。</p>}
      {incident.stop_reason && <p className={styles.note}>停止原因：{incident.stop_reason}</p>}
      {evidenceItems.length > 0 && <div className={styles.compactEvidence}>
        <h3>证据概览</h3>
        <button type="button" onClick={(event) => showEvidenceOverview(event.currentTarget)} aria-label={`打开证据概览，共 ${evidenceTotal ?? evidenceItems.length} 条`}>
          <span>{evidenceTotal === null ? `查看当前 ${evidenceItems.length} 条证据` : `查看全部 ${evidenceTotal} 条证据`}</span>
          <ArrowUpRight size={15} aria-hidden="true" />
        </button>
      </div>}
      {incident.response_plan && <div className={styles.responseSummary}>
        <h3>响应摘要</h3><p>{incident.response_plan.summary}</p>
        <Link href={`/responses/${encodeURIComponent(incident.response_plan.response_plan_id)}`}>查看响应方案 <ArrowUpRight size={14} aria-hidden="true" /></Link>
      </div>}
      {incident.validation_result && <div className={styles.responseSummary}>
        <h3>效果验证</h3><p>{incident.validation_result.summary}</p><span className={styles.listMeta}>结果：{incident.validation_result.outcome} · {formatTime(incident.validation_result.checked_at)}</span>
      </div>}
    </section>
  );
}

function StageList({ steps, graphNodes, selectedStepId, selectStep }: {
  steps: AttackStep[]; graphNodes: Map<string, GraphStep>; selectedStepId: string | null; selectStep: (id: string) => void;
}) {
  return <ol className={styles.stageList}>{steps.map((step) => {
    const node = graphNodes.get(step.attack_step_id);
    const details = stepDetails(step, node);
    return <li key={step.attack_step_id}>
    <button type="button" aria-pressed={selectedStepId === step.attack_step_id}
      data-support-status={node?.support_status ?? 'unknown'} data-step-id={step.attack_step_id} data-node-kind="stage"
      aria-label={`第 ${step.sequence} 步 ${step.description}`} onClick={() => selectStep(step.attack_step_id)}>
      <span className={styles.stageMarker} aria-hidden="true">
        <StepSphere phase={details.phase} supportStatus={node?.support_status ?? 'unknown'} selected={selectedStepId === step.attack_step_id} compact />
        <span className={styles.stageNumber}>{String(step.sequence).padStart(2, '0')}</span>
      </span>
      <span className={styles.stageBody}><strong>{step.description}</strong>
        <small>{details.phase} · {details.techniques} · {step.evidence_ids.length} 条证据引用</small>
        <StepMetadata step={step} node={node} /><small>{details.support}</small>
      </span>
      <ArrowUpRight size={16} aria-hidden="true" />
    </button>
  </li>;
  })}</ol>;
}

function EvidenceInspector({ incident, evidenceItems, evidenceTotal, evidencePageError, hasMoreEvidence,
  loadingMoreEvidence, retryEvidencePage, loadMoreEvidence, selectedStep, selectedGraphNode, selectedEvidenceId, selectEvidence }: {
  incident: IncidentSummary; selectedStep: AttackStep | undefined; selectedGraphNode?: GraphStep;
  evidenceItems: EvidenceItem[]; evidenceTotal: number | null; evidencePageError: Error | null;
  hasMoreEvidence: boolean; loadingMoreEvidence: boolean;
  retryEvidencePage: () => void; loadMoreEvidence: () => void;
  selectedEvidenceId: string | null; selectEvidence: (id: string) => void;
}) {
  const referenced = selectedStep?.evidence_ids ?? evidenceItems.map((item) => item.evidence_id);
  const selectedDetails = selectedStep ? stepDetails(selectedStep, selectedGraphNode) : null;
  const evidenceById = new Map([...incident.evidence, ...evidenceItems].map((item) => [item.evidence_id, item]));
  const evidence = selectedEvidenceId ? evidenceById.get(selectedEvidenceId) : undefined;
  const [sessionStarting, setSessionStarting] = useState(false);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const sessionQuery = useQuery({
    queryKey: ['demo-session'], queryFn: loadDemoSession, enabled: Boolean(evidence),
    retry: false, staleTime: 0, refetchInterval: 60_000,
  });
  const detailQuery = useQuery({
    queryKey: ['evidence', incident.incident_id, selectedEvidenceId],
    queryFn: ({ signal }) => loadEvidenceDetail(incident.incident_id, selectedEvidenceId!, signal),
    enabled: Boolean(evidence && sessionQuery.data && !sessionQuery.isFetching && !sessionQuery.isError),
    retry: false, staleTime: 0,
  });
  const detailFailure = detailQuery.error instanceof EvidenceDetailRequestError ? detailQuery.error : undefined;
  const sessionRequired = !sessionQuery.data || detailFailure?.status === 401 || detailFailure?.status === 403;
  const detail = detailQuery.data;
  const matchesSnapshot = Boolean(detail && evidence && detail.evidence.event_id === evidence.event_id &&
    detail.evidence.content_sha256 === evidence.content_sha256);

  async function enableDemoSession() {
    if (sessionStarting) return;
    setSessionStarting(true);
    setSessionError(null);
    try {
      await startDemoSession();
      const refreshed = await sessionQuery.refetch();
      if (!refreshed.data) throw new Error('会话未建立，请重试。');
      if (detailFailure?.status === 401 || detailFailure?.status === 403) await detailQuery.refetch();
    } catch (cause) {
      setSessionError(cause instanceof Error ? cause.message : '无法启用本地演示账户，请重试。');
    } finally {
      setSessionStarting(false);
    }
  }
  return <section className={styles.inspector} role="region" aria-label="证据检查器">
    <div className={styles.sectionHeading}><h2>证据检查器</h2><span>{referenced.length} 条引用</span></div>
    <div className={styles.inspectorBody}>
      <p className={styles.inspectorContext}>{selectedStep ? `第 ${selectedStep.sequence} 步引用的证据` : '当前案件已收集证据'}</p>
      {selectedStep && selectedDetails && <div className={styles.stepDetail}>
        <h3>步骤详情</h3><p>{selectedStep.description}</p>
        <dl className={styles.evidenceFacts}>
          <div><dt>阶段</dt><dd>{selectedDetails.phase}</dd></div>
          <div><dt>主机 / 服务</dt><dd>{selectedDetails.entities}</dd></div>
          <div><dt>观察时间（UTC+8）</dt><dd><StepTime value={selectedDetails.observedAt} /></dd></div>
          <div><dt>ATT&CK 技术</dt><dd>{selectedDetails.techniques}</dd></div>
          <div><dt>置信度</dt><dd>{selectedDetails.confidence}
            {selectedGraphNode?.confidence != null && <span className={styles.listMeta}>计算依据未提供；不表示校准后的发生概率。</span>}
          </dd></div>
          <div><dt>证据支持状态</dt><dd>{selectedDetails.support}</dd></div>
        </dl>
      </div>}
      {referenced.length ? <ul className={styles.evidenceList}>{referenced.map((id) => {
        const item = evidenceById.get(id);
        return <li key={id}>{item ? <button type="button" aria-pressed={selectedEvidenceId === id}
          onClick={() => selectEvidence(id)}><FileSearch size={16} aria-hidden="true" /><span><strong>{item.summary}</strong><small>{item.source} · {id}</small></span></button> :
          <div className={styles.missingEvidence}><ShieldAlert size={16} aria-hidden="true" /><span>{id}<small>引用的证据摘要未返回，无法查看或验证。</small></span></div>}</li>;
      })}</ul> : <p className={styles.empty}>尚无已收集证据。</p>}
      {!selectedStep && <p className={styles.evidenceCount}>{evidenceTotal === null ?
        `当前快照 ${evidenceItems.length} 条；服务端总数尚未核实。` :
        `已显示 ${evidenceItems.length} / ${evidenceTotal} 条`}</p>}
      {evidencePageError && <div className={styles.unavailable} role="alert">
        <p>{evidenceTotal === null ? '证据分页暂不可用，仅显示当前案件快照。' : '后续证据加载失败，已加载的证据仍可查看。'}</p>
        <p>{evidencePageError.message}</p>
        {evidencePageError instanceof EvidencePageRequestError && evidencePageError.traceId &&
          <p>Trace ID：<code>{evidencePageError.traceId}</code></p>}
        <Button autoInsertSpace={false} size="small" onClick={retryEvidencePage}>重试证据分页</Button>
      </div>}
      {!selectedStep && hasMoreEvidence && <Button autoInsertSpace={false} size="small"
        className={styles.loadMoreEvidence} loading={loadingMoreEvidence} disabled={loadingMoreEvidence || Boolean(evidencePageError)}
        onClick={loadMoreEvidence}>加载更多证据</Button>}
      {evidence ? <div className={styles.evidenceDetail}>
        <h3>证据摘要</h3>
        <dl className={styles.evidenceFacts}>
          <div><dt>Evidence ID</dt><dd className={styles.identifier}>{evidence.evidence_id}</dd></div>
          <div><dt>Event ID</dt><dd className={styles.identifier}>{evidence.event_id}</dd></div>
          <div><dt>来源</dt><dd>{evidence.source}</dd></div>
          <div><dt>观察时间（UTC+8）</dt><dd>{formatTime(evidence.observed_at)}</dd></div>
          <div><dt>引用步骤</dt><dd>{incident.attack_steps.filter((step) => step.evidence_ids.includes(evidence.evidence_id)).map((step) => `第 ${step.sequence} 步`).join('、') || '暂无步骤引用'}</dd></div>
        </dl>
        <h3>原始日志</h3>
        {sessionQuery.isPending || sessionQuery.isFetching ? <p className={styles.unavailable} role="status">正在检查演示账户…</p> :
          sessionRequired || sessionQuery.isError ? <div className={styles.unavailable} role="alert">
            <p>{detailFailure?.status === 401 ? '演示会话已失效，请重新启用后读取原始日志。' : '读取原始日志前请启用本地演示账户；证据摘要仍可查看。'}</p>
            {(sessionError || sessionQuery.isError) && <p>{sessionError || (sessionQuery.error instanceof Error ? sessionQuery.error.message : '会话服务暂时不可用。')}</p>}
            <Button autoInsertSpace={false} size="small" loading={sessionStarting}
              onClick={() => { void enableDemoSession(); }}>启用本地演示账户</Button>
          </div> : detailQuery.isPending ? <p className={styles.unavailable} role="status">正在读取授权原始日志与校验结果…</p> :
          detailQuery.isError ? <div className={styles.unavailable} role="alert">
            <p>{detailFailure?.status === 404 ? '证据不存在或无权访问，无法读取原文。' : detailFailure?.message ?? '证据详情加载失败。'}</p>
            {detailFailure?.traceId && <p>Trace ID：<code>{detailFailure.traceId}</code></p>}
            <Button autoInsertSpace={false} size="small" onClick={() => { void detailQuery.refetch(); }}>重试</Button>
          </div> : !matchesSnapshot ? <p className={styles.unavailable} role="alert">证据详情与当前案件快照不一致，请刷新案件后重新核对。</p> :
          <><p className={styles.fieldLabel}>服务端授权原始事件（{detail!.raw_access}）</p><pre className={styles.codeBlock}>{JSON.stringify(detail!.raw_event.raw, null, 2)}</pre></>}
        <h3>查询与校验</h3><p className={styles.fieldLabel}>检索查询</p><pre className={styles.codeBlock}>{JSON.stringify(evidence.query, null, 2)}</pre>
        <p className={styles.fieldLabel}>SHA-256（已记录内容哈希）</p><pre className={styles.codeBlock}>{evidence.content_sha256}</pre>
        {matchesSnapshot && detail ? <>
          <p role={detail.integrity.status === 'verified' ? 'status' : 'alert'}
            className={`${styles.integrityStatus} ${detail.integrity.status === 'verified' ? styles.integrityVerified :
              detail.integrity.status === 'mismatch' ? styles.integrityMismatch : styles.integrityWarning}`}>
            {detail.integrity.status === 'verified' ? 'PostgreSQL 本次校验通过' :
              detail.integrity.status === 'mismatch' ? 'PostgreSQL 本次校验哈希不匹配' : 'PostgreSQL 本次校验不可用'}
          </p>
          <p className={styles.integrityScope}>仅核对 PostgreSQL 中当前原始事件与证据记录；不表示 OpenSearch 或外部源已校验。算法 {detail.integrity.algorithm}，规范化 {detail.integrity.canonicalization}，校验时间（UTC+8）{formatTime(detail.integrity.checked_at)}。</p>
          <p className={styles.fieldLabel}>本次计算哈希</p><pre className={styles.codeBlock}>{detail.integrity.calculated_sha256 ?? '未计算'}</pre>
          <p className={styles.fieldLabel}>事件存储哈希</p><pre className={styles.codeBlock}>{detail.integrity.stored_event_sha256}</pre>
          <p className={styles.fieldLabel}>证据存储哈希</p><pre className={styles.codeBlock}>{detail.integrity.stored_evidence_sha256}</pre>
        </> : <p className={styles.unavailable}>尚不能验证当前原始内容与记录哈希是否一致。</p>}
      </div> : referenced.length ? <p className={styles.inspectorHint}>请选择一条证据查看查询与哈希。</p> : null}
    </div>
  </section>;
}

function RunInspector({ roleLabel, runs }: { roleLabel: string; runs: AgentRun[] }) {
  return <section className={styles.runInspector} role="region" aria-label={`${roleLabel}运行记录`}>
    <div className={styles.sectionHeading}><h2>{roleLabel}运行记录</h2><span>{runs.length} 条</span></div>
    <div className={styles.runInspectorBody}>
      <p className={styles.inspectorContext}>仅展示后端返回的真实运行时间、状态与证据引用。</p>
      <ol className={styles.runRecordList}>{runs.map((run) => <li key={run.run_id} className={styles.runRecord}>
        <strong className={styles.identifier}>{run.run_id}</strong><span className={styles.runRecordStatus}>{runLabels[run.status]}</span>
        <dl className={styles.runFacts}>
          <div><dt>角色</dt><dd>{run.agent_name}</dd></div>
          <div><dt>开始时间（UTC+8）</dt><dd>{formatTime(run.started_at)}</dd></div>
          <div><dt>结束时间（UTC+8）</dt><dd>{formatTime(run.finished_at)}</dd></div>
          <div><dt>证据引用</dt><dd>{run.evidence_ids.length ? run.evidence_ids.join('、') : '无'}</dd></div>
        </dl>
      </li>)}</ol>
    </div>
  </section>;
}

function AgentProgress({ incident, showRuns }: {
  incident: IncidentSummary; showRuns: (roleLabel: string, runs: AgentRun[], trigger: HTMLButtonElement) => void;
}) {
  return <section className={`${styles.panel} ${styles.progressPanel}`} role="region" aria-label="六角色进度">
    <div className={styles.sectionHeading}><h2>六角色进度</h2><span>{incident.runs.length} 条真实运行记录</span></div>
    <div className={styles.progressScroll}><ol className={styles.progressList}>{roleSteps.map((role) => {
      const runs = incident.runs.filter((run) => run.agent_name === role.key)
        .sort((a, b) => Date.parse(b.started_at) - Date.parse(a.started_at));
      const current = runs[0];
      const waitingForApproval = role.key === 'validate' && !current && incident.status === 'awaiting_approval';
      return <li key={role.key} className={styles.roleCard} data-status={current?.status ?? 'not_started'}>
        <div className={styles.roleTop}><span className={styles.roleMarker} aria-hidden="true" /><strong>{role.label}</strong></div>
        {current && <span className={styles.roleKey}>{current.agent_name}</span>}
        <span className={styles.roleStatus}>{current ? runLabels[current.status] : waitingForApproval ? '等待批准后执行' : '未开始'}</span>
        {current && <><span className={styles.roleTime}>{current.finished_at ? `完成：${formatTime(current.finished_at)}` : `开始：${formatTime(current.started_at)}`}</span>
          <button type="button" className={styles.runTrigger} aria-label={`查看${role.label}运行记录（${runs.length}）`}
            onClick={(event) => showRuns(role.label, runs, event.currentTarget)}>查看运行记录（{runs.length}） <ArrowUpRight size={13} aria-hidden="true" /></button></>}
      </li>;
    })}</ol></div>
    {incident.runs.some((run) => !roleSteps.some((role) => role.key === run.agent_name)) &&
      <p className={styles.note}>另有未映射到六角色的运行记录：{incident.runs.filter((run) => !roleSteps.some((role) => role.key === run.agent_name)).map((run) => `${run.agent_name} (${run.run_id})`).join('、')}</p>}
  </section>;
}

export default function IncidentWorkbench({ incident, attackGraph }: {
  incident: IncidentSummary; attackGraph?: AttackGraphData;
}) {
  const [chosenView, setChosenView] = useState<'graph' | 'list' | null>(null);
  const [selectedStepId, setSelectedStepId] = useState<string | null>(null);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const [drawerContent, setDrawerContent] = useState<
    { kind: 'evidence' } | { kind: 'runs'; roleLabel: string; runs: AgentRun[] } | null
  >(null);
  const drawerReturnFocus = useRef<HTMLElement | null>(null);
  const drawerFocusTimer = useRef<number | null>(null);
  const [layoutRevision, setLayoutRevision] = useState(0);
  const [phase, setPhase] = useState('all');
  const evidencePageQuery = useInfiniteQuery({
    queryKey: ['incident-evidence-page', incident.incident_id, incident.evidence.length],
    initialPageParam: 1,
    queryFn: ({ pageParam, signal }) => loadEvidencePage(incident.incident_id, pageParam, evidencePageSize, signal),
    getNextPageParam: (lastPage) => lastPage.items.length > 0 && lastPage.page * lastPage.page_size < lastPage.total
      ? lastPage.page + 1 : undefined,
    retry: false,
  });
  const pagedEvidence = evidencePageQuery.data?.pages.flatMap((page) => page.items) ?? null;
  const evidenceItems = pagedEvidence ?? incident.evidence;
  const evidenceTotal = evidencePageQuery.data?.pages.at(-1)?.total ?? null;
  const evidencePageError = evidencePageQuery.error;
  const retryEvidencePage = () => {
    if (evidencePageQuery.data) void evidencePageQuery.fetchNextPage();
    else void evidencePageQuery.refetch();
  };
  const loadMoreEvidence = () => { void evidencePageQuery.fetchNextPage(); };

  const mobile = useSyncExternalStore(subscribeMobile, getMobile, () => false);
  const view = chosenView ?? (mobile ? 'list' : 'graph');
  const selectedStep = incident.attack_steps.find((step) => step.attack_step_id === selectedStepId);
  const graphNodes = useMemo(() => new Map(attackGraph?.nodes.map((node) => [node.step_id, node]) ?? []), [attackGraph]);
  const selectedGraphNode = selectedStepId ? graphNodes.get(selectedStepId) : undefined;
  const phases = useMemo(() => [...new Set(incident.attack_steps.map((step) => step.phase ?? '阶段未提供'))], [incident.attack_steps]);
  const visibleSteps = useMemo(() => incident.attack_steps.filter((step) => phase === 'all' || (step.phase ?? '阶段未提供') === phase)
    .sort((a, b) => a.sequence - b.sequence || a.attack_step_id.localeCompare(b.attack_step_id)), [incident.attack_steps, phase]);
  const selectStep = useCallback((id: string) => {
    if (drawerFocusTimer.current !== null) window.clearTimeout(drawerFocusTimer.current);
    drawerReturnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setSelectedStepId(id);
    setSelectedEvidenceId(null);
    setDrawerContent({ kind: 'evidence' });
  }, []);
  const showEvidenceOverview = useCallback((trigger: HTMLButtonElement) => {
    if (drawerFocusTimer.current !== null) window.clearTimeout(drawerFocusTimer.current);
    drawerReturnFocus.current = trigger;
    setSelectedStepId(null);
    setSelectedEvidenceId(null);
    setDrawerContent({ kind: 'evidence' });
  }, []);
  const showRuns = useCallback((roleLabel: string, runs: AgentRun[], trigger: HTMLButtonElement) => {
    if (drawerFocusTimer.current !== null) window.clearTimeout(drawerFocusTimer.current);
    drawerReturnFocus.current = trigger;
    setDrawerContent({ kind: 'runs', roleLabel, runs });
  }, []);
  const closeDrawer = useCallback(() => {
    const target = drawerReturnFocus.current;
    drawerReturnFocus.current = null;
    setDrawerContent(null);
    if (drawerFocusTimer.current !== null) window.clearTimeout(drawerFocusTimer.current);
    drawerFocusTimer.current = window.setTimeout(() => {
      drawerFocusTimer.current = null;
      if (target?.isConnected) target.focus();
    }, 360);
  }, []);

  return <div className={styles.workbench}>
    <div className={styles.workbenchGrid} data-testid="workbench-grid">
      <aside className={styles.contextColumn}><ContextPanel incident={incident} evidenceItems={evidenceItems}
        evidenceTotal={evidenceTotal} showEvidenceOverview={showEvidenceOverview} /></aside>
      <div className={styles.primaryColumn}>
        <section className={`${styles.panel} ${styles.attackPanel}`} role="region" aria-label="攻击链">
          <div className={styles.sectionHeading}><h2>攻击链</h2><span>{incident.attack_steps.length} 步</span></div>
          <div className={styles.graphToolbar}>
            <div className={styles.viewSwitch} role="group" aria-label="攻击链视图">
              <button type="button" aria-pressed={view === 'graph'} onClick={() => setChosenView('graph')}>图谱</button>
              <button type="button" aria-pressed={view === 'list'} onClick={() => setChosenView('list')}>阶段列表</button>
            </div>
            <label>阶段 <select value={phase} onChange={(event) => setPhase(event.target.value)}>
              <option value="all">全部</option>{phases.map((value) => <option key={value} value={value}>{value}</option>)}
            </select></label>
            {view === 'graph' && incident.attack_steps.length > 0 && <Button autoInsertSpace={false} size="small" onClick={() => setLayoutRevision((value) => value + 1)}>重新布局</Button>}
          </div>
          <p className={styles.relationNotice}>{attackGraph?.edges.length ?
            '后端关系仅来自调查快照：实线箭头是时间先后，虚线箭头是因果候选，点线是行为关联；步骤排列不生成关系。' :
            '关系未知：当前数据只提供攻击步骤，未提供可核验的步骤间关系。序号仅用于排列，不代表因果或完整攻击路径。'}</p>
          {incident.attack_steps.length ? <>
            <div className={view === 'graph' ? styles.graphVisible : styles.graphHidden}>
              <AttackGraph key={layoutRevision} steps={visibleSteps} graph={attackGraph}
                selectedStepId={selectedStepId} selectStep={selectStep} />
            </div>
            {view === 'list' && <div className={styles.listVisible}>
              <StageList steps={visibleSteps} graphNodes={graphNodes} selectedStepId={selectedStepId} selectStep={selectStep} />
            </div>}
          </> : <p className={styles.empty}>尚无重构出的攻击步骤。</p>}
        </section>
        <AgentProgress incident={incident} showRuns={showRuns} />
      </div>
    </div>
    <Drawer title={drawerContent?.kind === 'runs' ? '运行记录' : '证据检查器'} placement="right" size="min(480px, 100vw)"
      open={drawerContent !== null} closeIcon={null}
      extra={<Button autoInsertSpace={false} onClick={closeDrawer}>关闭</Button>}
      onClose={closeDrawer} destroyOnHidden>
      {drawerContent?.kind === 'evidence' && <EvidenceInspector incident={incident} evidenceItems={evidenceItems} evidenceTotal={evidenceTotal}
        evidencePageError={evidencePageError} hasMoreEvidence={Boolean(evidencePageQuery.hasNextPage)}
        loadingMoreEvidence={evidencePageQuery.isFetchingNextPage} retryEvidencePage={retryEvidencePage}
        loadMoreEvidence={loadMoreEvidence} selectedStep={selectedStep} selectedGraphNode={selectedGraphNode} selectedEvidenceId={selectedEvidenceId}
        selectEvidence={setSelectedEvidenceId} />}
      {drawerContent?.kind === 'runs' && <RunInspector roleLabel={drawerContent.roleLabel} runs={drawerContent.runs} />}
    </Drawer>
  </div>;
}
