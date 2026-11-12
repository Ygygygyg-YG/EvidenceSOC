'use client';

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Button, Select } from 'antd';
import { Activity, AlertCircle, ArrowUpRight, Bell, Database, LoaderCircle, Search, ShieldCheck } from 'lucide-react';
import { buildAlertsQuery, severityLabels, statusLabels } from '../alerts/alertsContract';
import { dashboardAlertHref, dashboardIncidentHref, DashboardRequestError, loadDashboard, loadSourceHealth, readDashboardWindow,
  type DashboardData, type DashboardWindow, type SourceHealthData } from './dashboardContract';
import styles from './DashboardOverview.module.css';

const windows: { value: DashboardWindow; label: string }[] = [
  { value: '1h', label: '最近 1 小时' }, { value: '24h', label: '最近 24 小时' },
  { value: '7d', label: '最近 7 天' },
];
const timeFormatter = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', hour12: false,
});
const eventLabels: Record<string, string> = {
  'investigation.started': '调查启动', 'agent.started': '角色开始运行',
  'agent.completed': '角色运行完成', 'evidence.added': '新增证据',
  'approval.required': '等待人工审批', 'decision.recorded': '已记录人工决定',
  'validation.completed': '完成效果验证', 'investigation.completed': '调查完成',
  'investigation.failed': '调查失败',
};

function Time({ value }: { value: string }) {
  return <time dateTime={value} title={value}>{timeFormatter.format(new Date(value))}</time>;
}

function Trend({ data }: { data: DashboardData }) {
  const values = data.alert_trend;
  const maximum = Math.max(1, ...values.map((bucket) => bucket.total));
  const width = 760;
  const height = 200;
  const x = (index: number) => values.length < 2 ? width / 2 : index * width / (values.length - 1);
  const y = (value: number) => height - value * (height - 24) / maximum;
  const totalLine = values.map((bucket, index) => `${x(index)},${y(bucket.total)}`).join(' ');
  const highLine = values.map((bucket, index) => `${x(index)},${y(bucket.high_risk)}`).join(' ');
  return <>
    <div className={styles.chartInfo}>
      <p className={styles.chartSummary}>窗口内共 {data.metrics.alerts_in_window} 条告警；高危及严重告警 {values.reduce((sum, item) => sum + item.high_risk, 0)} 条。</p>
      <div className={styles.chartLegend}><span className={styles.legendTotal}>总告警</span><span className={styles.legendHigh}>高危及严重</span></div>
    </div>
    <Link href={dashboardAlertHref(data)} aria-label="查看窗口告警列表" className={styles.chartLink}><svg className={styles.trendSvg} role="img" aria-label="窗口内告警趋势：总告警和高危及严重告警" viewBox={`-16 -8 ${width + 32} ${height + 24}`} preserveAspectRatio="none">
      <g aria-hidden="true" className={styles.chartGrid}>
        <line x1="0" y1="24" x2={width} y2="24" />
        <line x1="0" y1={(height + 24) / 2} x2={width} y2={(height + 24) / 2} />
      </g>
      <line x1="0" y1={height} x2={width} y2={height} className={styles.axis} />
      {values.length > 0 && <>
        {values.length > 1 && <polygon points={`0,${height} ${totalLine} ${width},${height}`} className={styles.totalArea} aria-hidden="true" />}
        <polyline points={totalLine} className={styles.totalLine} />
        <polyline points={highLine} className={styles.highLine} />
      </>}
    </svg></Link>
    <div className={styles.chartEnds}><span><Time value={data.time_from} /></span><span><Time value={data.time_to} /></span></div>
    <details className={styles.chartTable}><summary>查看每个时间段的准确数量</summary>
      <div className={styles.tableScroller}><table><thead><tr><th scope="col">时间段起点</th><th scope="col">告警</th><th scope="col">高危及严重</th></tr></thead>
        <tbody>{values.map((bucket) => <tr key={bucket.bucket_start}>
          <td><Time value={bucket.bucket_start} /></td><td><Link href={dashboardAlertHref(data, bucket)} aria-label={`查看 ${bucket.bucket_start} 时间段的 ${bucket.total} 条告警`}>{bucket.total}</Link></td><td>{bucket.high_risk}</td>
        </tr>)}</tbody></table></div>
    </details>
  </>;
}

function StatusDistribution({ data }: { data: DashboardData }) {
  const rows = data.incident_status_distribution;
  const maximum = Math.max(1, ...rows.map((row) => row.count));
  return rows.length ? <ul className={styles.statusBars}>{rows.map((row) => <li key={row.status} data-status={row.status}>
    <div><Link href={dashboardIncidentHref(data, { status: row.status })}>{statusLabels[row.status]}</Link><strong>{row.count}</strong></div>
    <span className={styles.barTrack}><span style={{ width: `${row.count / maximum * 100}%` }} /></span>
  </li>)}</ul> : <div className={styles.emptyState}><Activity size={24} aria-hidden="true" /><p>窗口内没有调查记录。</p></div>;
}

function Health({ health }: { health: SourceHealthData }) {
  return <div className={styles.healthBody}>
    <p>健康状态来自当前可核实的后端信息；未知不代表正常。检查时间（UTC+8）：<Time value={health.checked_at} /></p>
    <dl className={styles.healthGrid}>
      <div><dt>PostgreSQL</dt><dd data-health-status={health.postgresql_status ?? 'unknown'}>{health.postgresql_status === 'ok' ? '连接正常' : health.postgresql_status ?? '未知'}</dd></div>
      <div><dt>OpenSearch</dt><dd data-health-status={health.opensearch_status ?? 'unknown'}>{health.opensearch_status === 'ok' ? '连接正常' : health.opensearch_status ?? '未知'}</dd></div>
      <div><dt>日志源数量</dt><dd>{health.sources.length}</dd></div>
      <div><dt>索引延迟</dt><dd>未获得</dd></div>
    </dl>
    {health.sources.length ? <ul className={styles.sourceList}>{health.sources.map((source) => <li key={source.source}>
      <strong>{source.source}</strong><span>最后入库：<Time value={source.last_ingested_at} /></span>
      <span>距最后入库：{source.ingestion_lag_seconds === null ? '未知' : `${source.ingestion_lag_seconds} 秒`}</span>
      <span>{source.status ?? '状态未知'}</span>
    </li>)}</ul> : <p className={styles.emptyInline}>尚无已入库的日志源。</p>}
  </div>;
}

export default function DashboardOverview() {
  const router = useRouter();
  const params = useSearchParams();
  const window = readDashboardWindow(params);
  const query = useQuery({ queryKey: ['dashboard-summary', window],
    queryFn: ({ signal }) => loadDashboard(window, signal), retry: false, staleTime: 30_000 });
  const healthQuery = useQuery({ queryKey: ['source-health'],
    queryFn: ({ signal }) => loadSourceHealth(signal), retry: false, staleTime: 30_000 });
  const data = query.data;
  const alertListHref = data ? dashboardAlertHref(data) : '/alerts';
  const alertListQuery = data ? buildAlertsQuery({ page: 1, pageSize: 20, timeFrom: data.time_from, timeTo: data.time_to }) : '';
  const error = query.error instanceof DashboardRequestError ? query.error : null;

  return <div className={styles.page}>
    <header className={styles.pageHeader}>
      <div><p className={styles.eyebrow} aria-hidden="true">SECURITY OPERATIONS / OVERVIEW</p><h1>运营总览</h1><p>真实统计按所选窗口聚合，当前待审批与运行中状态截至窗口结束时计算。</p></div>
      <div className={styles.windowActions}><Select<DashboardWindow> aria-label="统计时间窗口" virtual={false}
        value={window} options={windows} onChange={(next) => router.push(`/?window=${next}`, { scroll: false })} />
        <Button autoInsertSpace={false} loading={query.isFetching} onClick={() => { void query.refetch(); }}>刷新</Button></div>
    </header>
    {!data && (query.isPending || query.isFetching) ? <div className={styles.state} role="status"><LoaderCircle size={26} aria-hidden="true" /><p>正在读取运营统计…</p></div>
      : !data && query.isError ? <div className={styles.state} role="alert"><AlertCircle size={26} aria-hidden="true" />
        <h2>运营统计加载失败</h2><p>{error?.message ?? '请求失败，请重试。'}</p>
        {error && <p>错误代码：{error.code}</p>}{error?.traceId && <p>Trace ID：<code>{error.traceId}</code></p>}
        <Button autoInsertSpace={false} onClick={() => { void query.refetch(); }}>重试</Button>
      </div> : data ? <>
        {query.isError && <div className={styles.notice} role="alert">更新失败，显示上次成功的统计。{error?.message ?? ''}
          {error?.traceId && <> Trace ID：<code>{error.traceId}</code></>}</div>}
        <p className={styles.windowCaption}>运行模式：{data.execution_mode === 'rules' ? '规则演示' : '模型调查'}。统计窗口（UTC+8）：<Time value={data.time_from} /> 至 <Time value={data.time_to} />；生成于 <Time value={data.generated_at} />。进入列表后可继续核对明细。</p>
        <div className={styles.dashboard}>
          <dl className={styles.metricGrid} data-testid="overview-metrics">
            <div className={styles.metric}><dt>窗口内告警<Bell size={16} aria-hidden="true" /></dt><dd className={styles.metricValue}>{data.metrics.alerts_in_window}</dd><dd className={styles.metricNote}><Link href={alertListHref}>查看告警列表<ArrowUpRight size={13} aria-hidden="true" /></Link></dd></div>
            <div className={styles.metric}><dt>窗口内高危调查<Search size={16} aria-hidden="true" /></dt><dd className={styles.metricValue}>{data.metrics.high_risk_incidents}</dd><dd className={styles.metricNote}><Link href={dashboardIncidentHref(data, { risk: 'high' })}>查看调查列表<ArrowUpRight size={13} aria-hidden="true" /></Link></dd></div>
            <div className={styles.metric}><dt>当前运行中调查<Activity size={16} aria-hidden="true" /></dt><dd className={styles.metricValue}>{data.metrics.running_investigations}</dd><dd className={styles.metricNote}>全量现态 · <Link href="/incidents">查看调查列表<ArrowUpRight size={13} aria-hidden="true" /></Link></dd></div>
            <div className={styles.metric}><dt>当前待审批方案<ShieldCheck size={16} aria-hidden="true" /></dt><dd className={styles.metricValue}>{data.metrics.pending_response_plans}</dd><dd className={styles.metricNote}><Link href="/responses?decision_state=pending">查看响应队列<ArrowUpRight size={13} aria-hidden="true" /></Link></dd></div>
          </dl>
          <div className={styles.rowGrid}>
            <section className={`${styles.panel} ${styles.wide}`} aria-labelledby="alert-trend-title">
              <header className={styles.panelHeader}><h2 id="alert-trend-title">告警趋势</h2><span className={styles.panelMeta}>{windows.find((item) => item.value === window)?.label}</span></header>
              <div className={styles.chartBody}><Trend data={data} /></div>
            </section>
            <section className={`${styles.panel} ${styles.narrow}`} aria-labelledby="investigation-status-title">
              <header className={styles.panelHeader}><h2 id="investigation-status-title">窗口内调查状态</h2></header>
              <StatusDistribution data={data} />
            </section>
          </div>
          <div className={styles.rowGrid}>
            <section className={`${styles.panel} ${styles.wide}`} aria-labelledby="recent-alerts-title">
              <header className={styles.panelHeader}><h2 id="recent-alerts-title"><Bell size={18} aria-hidden="true" />最近告警</h2><Link href={alertListHref}>查看全部<ArrowUpRight size={13} aria-hidden="true" /></Link></header>
              {data.recent_alerts.length ? <ul className={styles.recentList}>{data.recent_alerts.map((alert) => <li key={alert.alert_id}>
                <Link href={`/alerts/${encodeURIComponent(alert.alert_id)}?from=${encodeURIComponent(alertListQuery)}`}>{alert.title}</Link>
                <span className={styles.alertState}><span className={styles.severity} data-severity={alert.severity}>{severityLabels[alert.severity]}</span> · {statusLabels[alert.status]}</span><Time value={alert.created_at} />
              </li>)}</ul> : <div className={styles.emptyState}><Bell size={24} aria-hidden="true" /><p>窗口内没有告警。</p></div>}
            </section>
            <section className={`${styles.panel} ${styles.narrow}`} aria-labelledby="recent-activity-title">
              <header className={styles.panelHeader}><h2 id="recent-activity-title">近期活动</h2></header>
              {data.recent_activity.length ? <ol className={styles.activityList}>{data.recent_activity.map((activity, index) => <li key={`${activity.investigation_id}-${activity.occurred_at}-${index}`}>
                <Link href={`/incidents/${encodeURIComponent(activity.incident_id)}`}>{eventLabels[activity.event] ?? activity.event}</Link>
                <small>{activity.incident_id} · <Time value={activity.occurred_at} /></small>
              </li>)}</ol> : <div className={styles.emptyState}><Activity size={24} aria-hidden="true" /><p>窗口内没有调查活动。</p></div>}
            </section>
          </div>
          <section className={styles.panel} aria-labelledby="source-health-title">
            <header className={styles.panelHeader}><h2 id="source-health-title"><Database size={18} aria-hidden="true" />数据源健康</h2><span className={styles.panelMeta}>实时可核实项与未知项</span></header>
            {healthQuery.data ? <Health health={healthQuery.data} /> : healthQuery.isError ?
              <div className={styles.healthBody} role="alert"><p>数据源健康读取失败。{healthQuery.error instanceof DashboardRequestError ? healthQuery.error.message : '请重试。'}</p>
                <Button autoInsertSpace={false} onClick={() => { void healthQuery.refetch(); }}>重试健康检查</Button></div> :
              <div className={styles.healthBody} role="status"><p>正在读取数据源健康…</p></div>}
          </section>
        </div>
      </> : null}
  </div>;
}
