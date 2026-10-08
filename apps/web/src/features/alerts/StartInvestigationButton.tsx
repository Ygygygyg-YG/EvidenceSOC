'use client';

import { useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Button } from 'antd';
import { AlertRequestError } from './alertsContract';
import { startInvestigation } from './alertDetailContract';
import { loadDemoSession, startDemoSession } from '../responses/sessionContract';
import styles from './AlertDetail.module.css';

export default function StartInvestigationButton({ alertId, mode }: { alertId: string; mode: 'rules' | 'model' }) {
  const router = useRouter();
  const inFlight = useRef(false);
  const idempotencyKey = useRef<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<AlertRequestError | null>(null);
  const [sessionStarting, setSessionStarting] = useState(false);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const sessionQuery = useQuery({
    queryKey: ['demo-session'], queryFn: loadDemoSession, retry: false,
    staleTime: 0, refetchInterval: 60_000,
  });

  async function enableDemoSession() {
    if (sessionStarting) return;
    setSessionStarting(true);
    setSessionError(null);
    try {
      await startDemoSession();
      const refreshed = await sessionQuery.refetch();
      if (!refreshed.data) throw new Error('会话未建立，请重试。');
    } catch (cause) {
      setSessionError(cause instanceof Error ? cause.message : '无法启用本地演示账户，请重试。');
    } finally {
      setSessionStarting(false);
    }
  }

  async function submit() {
    if (inFlight.current || !sessionQuery.data || sessionQuery.isFetching || sessionQuery.isError) return;
    inFlight.current = true;
    setSubmitting(true);
    setError(null);
    try {
      idempotencyKey.current ??= crypto.randomUUID();
      const accepted = await startInvestigation(alertId, mode, idempotencyKey.current);
      router.push(`/incidents/${encodeURIComponent(accepted.incident_id)}`);
    } catch (cause) {
      const failure = cause instanceof AlertRequestError ? cause
        : new AlertRequestError('UNKNOWN_ERROR', '启动调查失败。请刷新告警详情，确认是否已经创建调查。');
      setError(failure);
      if (failure.status === 401 || failure.status === 403) await sessionQuery.refetch();
      inFlight.current = false;
      setSubmitting(false);
    }
  }

  return <div className={styles.startAction}>
    {!sessionQuery.data && !sessionQuery.isPending && <p>启动调查前请启用本地演示账户。</p>}
    {sessionQuery.data && <p>当前演示账户：<code>{sessionQuery.data.actor_id}</code></p>}
    {(sessionError || sessionQuery.isError) && <p className={styles.actionError} role="alert">{sessionError || (sessionQuery.error instanceof Error ? sessionQuery.error.message : '会话服务暂时不可用。')}</p>}
    {(!sessionQuery.data || sessionQuery.isError) && <Button autoInsertSpace={false} loading={sessionStarting}
      onClick={() => { void enableDemoSession(); }}>启用本地演示账户</Button>}
    {error && <div className={styles.actionError} role="alert">
      <p>{error.message}</p>
      <p>错误代码：{error.code}</p>
      {error.traceId && <p>Trace ID：<code>{error.traceId}</code></p>}
    </div>}
    <Button type="primary" loading={submitting} disabled={submitting || !sessionQuery.data || sessionQuery.isFetching || sessionQuery.isError} onClick={() => { void submit(); }}>
      启动调查
    </Button>
  </div>;
}
