'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Button } from 'antd';
import { AlertCircle, ArrowLeft, LoaderCircle } from 'lucide-react';
import Link from 'next/link';
import { IncidentRequestError, loadIncident } from './incidentContract';
import { incidentListReturnHref } from './incidentsListContract';
import IncidentWorkbench from './IncidentWorkbench';
import type { InvestigationSnapshot } from './investigationSnapshotContract';
import { useInvestigationStream } from './useInvestigationStream';
import styles from './IncidentDetail.module.css';

export default function IncidentDetail({ id, from }: { id: string; from?: string | null }) {
  const [snapshot, setSnapshot] = useState<InvestigationSnapshot | null>(null);
  const [streamRetryKey, setStreamRetryKey] = useState(0);
  const query = useQuery({
    queryKey: ['incident', id], queryFn: ({ signal }) => loadIncident(id, signal),
    retry: false, staleTime: 0,
  });
  const failure = query.error instanceof IncidentRequestError ? query.error : undefined;
  const missing = failure?.status === 404;
  const currentSnapshot = snapshot?.incident_id === id ? snapshot : null;
  const incident = currentSnapshot ?? query.data;
  const investigationId = incident?.investigation_id ?? null;
  const stream = useInvestigationStream(investigationId, !!investigationId, (latest) => {
    if (latest.incident_id !== id) return;
    setSnapshot((previous) => previous?.incident_id === id && BigInt(previous.revision) > BigInt(latest.revision)
      ? previous : latest);
  }, streamRetryKey);
  function refresh(): void {
    if (investigationId) setStreamRetryKey((value) => value + 1);
    else void query.refetch();
  }

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <Link href={incidentListReturnHref(from)} className={styles.backLink}><ArrowLeft size={16} aria-hidden="true" />{from ? '返回调查列表' : '返回告警列表'}</Link>
        <div className={styles.titleRow}>
          <div><h1>案件详情</h1><p>查看攻击步骤、证据引用与调查进度。</p></div>
          {incident && <Button autoInsertSpace={false} loading={query.isFetching} onClick={refresh}>刷新</Button>}
        </div>
        {stream === 'connecting' && <p className={styles.streamState} role="status">正在校准调查快照与事件游标。</p>}
        {stream === 'live' && <p className={styles.streamState} role="status">调查事件已连接，变化会自动更新。</p>}
        {stream === 'reconnecting' && <p className={styles.streamState} role="status">事件流断线，正在重连；也可以手动刷新。</p>}
        {stream === 'offline' && <p className={styles.streamState} role="alert">调查快照暂时无法校准；当前内容可能过期。点击刷新重试。</p>}
        {stream === 'unauthorized' && <p className={styles.streamState} role="alert">会话已失效，调查事件已停止更新。请重新认证后点击刷新。</p>}
        {stream === 'forbidden' && <p className={styles.streamState} role="alert">当前账户无权查看此调查，事件已停止更新。请返回有权限的页面。</p>}
      </header>
      <div className={styles.workspace} role="region" aria-label="案件工作区">
        {!incident && (query.isPending || query.isFetching) ? (
          <div className={styles.state} role="status"><LoaderCircle size={28} aria-hidden="true" /><p>正在加载案件…</p></div>
        ) : !incident && query.isError ? (
          <div className={styles.state} role="alert">
            <AlertCircle size={28} aria-hidden="true" />
            <h2>{missing ? '案件不存在' : '案件加载失败'}</h2>
            <p>{missing ? '该案件编号没有对应记录，请核对链接。' : failure?.message ?? '案件请求失败，请重试。'}</p>
            {!missing && failure && <p className={styles.errorCode}>错误代码：{failure.code}</p>}
            {!missing && failure?.traceId && <p className={styles.trace}>Trace ID：<code>{failure.traceId}</code></p>}
            {!missing && <Button autoInsertSpace={false} onClick={() => { void query.refetch(); }}>重试</Button>}
          </div>
        ) : incident ? (
          <>
            {query.isFetching ? <div className={styles.notice} role="status">正在更新，展示上次成功结果。</div> :
              query.isError ? <div className={styles.notice} role="alert">
                更新失败，展示上次成功结果。{failure?.message} {failure?.traceId && <>Trace ID：<code>{failure.traceId}</code></>}
                <Button autoInsertSpace={false} onClick={() => { void query.refetch(); }}>重试</Button>
              </div> : null}
            <IncidentWorkbench incident={incident} attackGraph={currentSnapshot?.attack_graph} />
          </>
        ) : null}
      </div>
    </div>
  );
}
