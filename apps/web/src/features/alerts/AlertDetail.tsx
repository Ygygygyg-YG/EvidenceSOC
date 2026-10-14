'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Button } from 'antd';
import { AlertCircle, LoaderCircle } from 'lucide-react';
import { AlertRequestError, buildAlertsQuery, readAlertFilters, severityLabels, statusLabels } from './alertsContract';
import { loadAlertDetail } from './alertDetailContract';
import StartInvestigationButton from './StartInvestigationButton';
import styles from './AlertDetail.module.css';

const dateFormatter = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
});

function Time({ value }: { value: string }) {
  return <time dateTime={value} title={value}>{dateFormatter.format(new Date(value))}</time>;
}

export default function AlertDetail({ id }: { id: string }) {
  const params = useSearchParams();
  const from = params.get('from');
  const backHref = from === null ? '/alerts' : `/alerts?${buildAlertsQuery(readAlertFilters(new URLSearchParams(from)))}`;
  const query = useQuery({ queryKey: ['alert-detail', id], queryFn: ({ signal }) => loadAlertDetail(id, signal), retry: false, staleTime: 0 });
  const error = query.error instanceof AlertRequestError ? query.error : null;
  const detail = query.data;

  return <div className={styles.page}>
    <Link className={styles.backLink} href={backHref}>返回告警列表</Link>
    {!detail && query.isPending ? <div className={styles.state} role="status"><LoaderCircle aria-hidden="true" size={26} /><p>正在加载告警详情…</p></div>
      : !detail && query.isError ? <div className={styles.state} role="alert">
        <AlertCircle aria-hidden="true" size={26} />
        <h1>{error?.status === 404 ? '告警不存在' : '告警详情加载失败'}</h1>
        <p>{error?.status === 404 ? '这个告警可能已被移除，请返回列表确认。' : error?.message ?? '请求失败，请重试。'}</p>
        {error && <p>错误代码：{error.code}</p>}
        {error?.traceId && <p>Trace ID：<code>{error.traceId}</code></p>}
        <Button onClick={() => { void query.refetch(); }}>重试</Button>
      </div> : detail ? <>
        <header className={styles.header}>
          <div>
            <h1>{detail.title}</h1>
            <p className={styles.identifier}>{detail.alert_id}</p>
          </div>
          <div className={styles.badges}><span>{severityLabels[detail.severity]}</span><span>{statusLabels[detail.status]}</span></div>
        </header>
        {query.isError && <div className={styles.refreshError} role="alert">
          <p>更新失败，展示上次读取的告警。{error?.message ?? ''}</p>
          {error?.traceId && <p>Trace ID：<code>{error.traceId}</code></p>}
          <Button onClick={() => { void query.refetch(); }}>重试</Button>
        </div>}
        <section className={styles.panel} aria-labelledby="alert-summary-heading">
          <h2 id="alert-summary-heading">告警摘要</h2>
          <dl className={styles.summary}>
            <div><dt>创建时间（UTC+8）</dt><dd><Time value={detail.created_at} /></dd></div>
            <div><dt>严重性</dt><dd>{severityLabels[detail.severity]}</dd></div>
            <div><dt>当前状态</dt><dd>{statusLabels[detail.status]}</dd></div>
            <div><dt>调查执行方式</dt><dd>当前运行模式：{detail.execution_mode === 'rules' ? '规则模式' : '模型模式'}</dd></div>
            <div><dt>关联日志</dt><dd>{detail.events.length} 条</dd></div>
          </dl>
        </section>
        <section className={styles.panel} aria-labelledby="event-heading">
          <h2 id="event-heading">关联日志</h2>
          <div className={styles.tableScroller}>
            <table className={styles.table} aria-label="关联日志">
              <thead><tr><th scope="col">日志编号</th><th scope="col">观测时间（UTC+8）</th><th scope="col">来源</th><th scope="col">类型</th><th scope="col">严重性</th></tr></thead>
              <tbody>{detail.events.map((event) => <tr key={event.event_id}>
                <td><code>{event.event_id}</code></td><td><Time value={event.observed_at} /></td>
                <td>{event.source}</td><td>{event.event_type}</td><td>{severityLabels[event.severity]}</td>
              </tr>)}</tbody>
            </table>
          </div>
        </section>
        <section className={styles.panel} aria-labelledby="investigation-heading">
          <h2 id="investigation-heading">调查记录</h2>
          {detail.investigation_id && detail.incident_id ? <div className={styles.investigation}>
            <div><p>案件编号：<code>{detail.incident_id}</code></p>
              {detail.investigation_id && <p>调查编号：<code>{detail.investigation_id}</code></p>}</div>
            <Link className={styles.primaryLink} href={`/incidents/${encodeURIComponent(detail.incident_id)}`}>继续调查</Link>
          </div> : <div className={styles.investigation}>
            <div>{detail.incident_id && <p>已有案件：<code>{detail.incident_id}</code></p>}
              <p>尚未创建调查。启动后可在案件页查看进度和结果。</p></div>
            <StartInvestigationButton alertId={detail.alert_id} mode={detail.execution_mode} />
          </div>}
        </section>
      </> : null}
  </div>;
}
