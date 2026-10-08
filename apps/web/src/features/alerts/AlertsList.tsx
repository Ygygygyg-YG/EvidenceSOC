'use client';

import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Button, Select } from 'antd';
import { AlertCircle, Bell, CircleHelp, LoaderCircle } from 'lucide-react';
import { socTokens as t } from '@/lib/theme/socTokens';
import {
  AlertRequestError, buildAlertsQuery, changeAlertFilters,
  loadAlerts, pageSizeOptions, readAlertFilters, severityLabels, severityValues,
  resolveShanghaiDateTimeInput, statusLabels, statusValues, toShanghaiDateTimeInput,
  type AlertFilters, type AlertListItem, type IncidentStatus, type Severity,
} from './alertsContract';
import styles from './AlertsList.module.css';

const severityColors: Record<Severity, string> = {
  info: t.textSecondary, low: t.primary, medium: t.warning, high: t.error, critical: t.error,
};
const dateFormatter = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
});

function SeverityLabel({ severity }: { severity: Severity }) {
  return <span className={styles.badge} style={{ color: severityColors[severity] }}>{severityLabels[severity]}</span>;
}

function CreatedTime({ alert }: { alert: AlertListItem }) {
  return <time dateTime={alert.created_at} title={alert.created_at}>{dateFormatter.format(new Date(alert.created_at))}</time>;
}

export default function AlertsList() {
  const searchParams = useSearchParams();
  const filters = readAlertFilters(searchParams);
  const queryString = buildAlertsQuery(filters);
  return <AlertsListContent key={queryString} filters={filters} queryString={queryString} />;
}

function AlertsListContent({ filters, queryString }: { filters: AlertFilters; queryString: string }) {
  const router = useRouter();
  const [keyword, setKeyword] = useState(filters.query ?? '');
  const [timeFrom, setTimeFrom] = useState(filters.timeFrom ? toShanghaiDateTimeInput(filters.timeFrom) : '');
  const [timeTo, setTimeTo] = useState(filters.timeTo ? toShanghaiDateTimeInput(filters.timeTo) : '');
  const [timeError, setTimeError] = useState(false);
  const keywordTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (keywordTimer.current) clearTimeout(keywordTimer.current); }, []);
  const detailHref = (id: string) => `/alerts/${encodeURIComponent(id)}?from=${encodeURIComponent(queryString)}`;
  const query = useQuery({
    queryKey: ['alerts', queryString], queryFn: ({ signal }) => loadAlerts(filters, signal),
    retry: false, staleTime: 0,
  });
  const navigate = (next: AlertFilters) => {
    if (keywordTimer.current) clearTimeout(keywordTimer.current);
    router.push(`/alerts?${buildAlertsQuery(next)}`, { scroll: false });
  };
  const changeExplicitFilter = (patch: Partial<Pick<AlertFilters, 'severity' | 'status' | 'pageSize'>>) =>
    navigate(changeAlertFilters(filters, { ...patch, query: keyword }));
  const applyTime = () => {
    const from = resolveShanghaiDateTimeInput(timeFrom, filters.timeFrom);
    const to = resolveShanghaiDateTimeInput(timeTo, filters.timeTo);
    if (!from || !to || Date.parse(from) >= Date.parse(to)) { setTimeError(true); return; }
    setTimeError(false);
    navigate(changeAlertFilters(filters, { timeFrom: from, timeTo: to, query: keyword }));
  };
  const changeKeyword = (value: string) => {
    setKeyword(value);
    if (keywordTimer.current) clearTimeout(keywordTimer.current);
    keywordTimer.current = setTimeout(() => {
      router.push(`/alerts?${buildAlertsQuery(changeAlertFilters(filters, { query: value }))}`, { scroll: false });
    }, 300);
  };
  const successfulData = query.data;
  const loading = !successfulData && (query.isPending || query.isFetching);
  const failure = query.error instanceof AlertRequestError ? query.error : undefined;
  const filtered = Boolean(filters.severity || filters.status || filters.timeFrom || filters.query);

  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <h1>告警列表</h1>
        <p>按时间、严重性、当前状态和关键词查看告警。记录按创建时间从新到旧排列。</p>
      </header>
      <section className={styles.panel} aria-label="告警工作区">
        <div className={styles.filters}>
          <label className={styles.filter} htmlFor="alerts-severity">
            <span>严重性</span>
            <Select<Severity | 'all'> id="alerts-severity" aria-label="严重性" virtual={false}
              value={filters.severity ?? 'all'}
              options={[{ value: 'all', label: '全部严重性' }, ...severityValues.map((value) => ({ value, label: severityLabels[value] }))]}
              onChange={(value) => changeExplicitFilter({ severity: value === 'all' ? undefined : value })} />
          </label>
          <label className={styles.filter} htmlFor="alerts-status">
            <span>当前状态</span>
            <Select<IncidentStatus | 'all'> id="alerts-status" aria-label="当前状态" virtual={false}
              value={filters.status ?? 'all'}
              options={[{ value: 'all', label: '全部状态' }, ...statusValues.map((value) => ({ value, label: statusLabels[value] }))]}
              onChange={(value) => changeExplicitFilter({ status: value === 'all' ? undefined : value })} />
          </label>
          <label className={`${styles.filter} ${styles.queryFilter}`} htmlFor="alerts-query">
            <span>关键词</span>
            <input id="alerts-query" aria-label="关键词" className={styles.textInput} type="search" maxLength={200}
              placeholder="标题或告警编号" value={keyword} onChange={(event) => changeKeyword(event.target.value)} />
          </label>
          <label className={`${styles.filter} ${styles.timeFilter}`} htmlFor="alerts-time-from">
            <span>开始时间（UTC+8）</span>
            <input id="alerts-time-from" className={styles.textInput} type="datetime-local" step={1}
              value={timeFrom} onChange={(event) => { setTimeFrom(event.target.value); setTimeError(false); }} />
          </label>
          <label className={`${styles.filter} ${styles.timeFilter}`} htmlFor="alerts-time-to">
            <span>结束时间（UTC+8）</span>
            <input id="alerts-time-to" className={styles.textInput} type="datetime-local" step={1}
              value={timeTo} onChange={(event) => { setTimeTo(event.target.value); setTimeError(false); }} />
          </label>
          <div className={styles.rangeActions}>
            <Button onClick={applyTime}>应用时间</Button>
            <Button onClick={() => { setTimeFrom(''); setTimeTo(''); setTimeError(false);
              navigate(changeAlertFilters(filters, { timeFrom: undefined, timeTo: undefined, query: keyword })); }}>清除时间</Button>
          </div>
          <label className={styles.filter} htmlFor="alerts-page-size">
            <span>每页条数</span>
            <Select<number> id="alerts-page-size" aria-label="每页条数" virtual={false}
              value={filters.pageSize} options={pageSizeOptions.map((value) => ({ value, label: `${value} 条/页` }))}
              onChange={(pageSize) => changeExplicitFilter({ pageSize })} />
          </label>
        </div>
        {timeError && <p className={styles.filterError} role="alert">请选择有效的开始和结束时间，结束时间必须晚于开始时间。</p>}
        <p className={styles.statusNote}>时间区间按创建时间筛选，包含开始、不包含结束。当前状态来自最近一次关联调查；无调查时显示“已接收”。</p>

        {loading ? (
          <div className={styles.state} role="status"><LoaderCircle size={28} aria-hidden="true" /><p>正在加载告警…</p></div>
        ) : !successfulData && query.isError ? (
          <div className={`${styles.state} ${styles.errorState}`} role="alert">
            <AlertCircle size={28} aria-hidden="true" />
            <h2>告警加载失败</h2>
            <p>{failure?.message ?? '告警请求失败，请重试。'}</p>
            {failure && <p className={styles.errorCode}>错误代码：{failure.code}</p>}
            {failure?.traceId && <p className={styles.trace}>Trace ID：<code>{failure.traceId}</code></p>}
            <Button autoInsertSpace={false} onClick={() => { void query.refetch(); }}>重试</Button>
          </div>
        ) : successfulData ? (
          <>
            {query.isFetching ? (
              <div className={styles.updateNotice} role="status">
                <LoaderCircle size={18} aria-hidden="true" /><p>正在更新，展示上次成功结果。</p>
              </div>
            ) : query.isError ? (
              <div className={styles.updateNotice} role="alert">
                <AlertCircle size={18} aria-hidden="true" />
                <div className={styles.updateMessage}>
                  <p>更新失败，展示上次成功结果。</p>
                  <p>{failure?.message ?? '告警请求失败，请重试。'}</p>
                  {failure && <p className={styles.errorCode}>错误代码：{failure.code}</p>}
                  {failure?.traceId && <p className={styles.trace}>Trace ID：<code>{failure.traceId}</code></p>}
                </div>
                <Button autoInsertSpace={false} onClick={() => { void query.refetch(); }}>重试</Button>
              </div>
            ) : null}
            <div className={styles.summary}>
              <h2>告警记录</h2>
              <div className={styles.summaryActions}>
                <span data-testid="alerts-total">共 {successfulData.total} 条告警</span>
                <Button autoInsertSpace={false} loading={query.isFetching} onClick={() => { void query.refetch(); }}>刷新</Button>
              </div>
            </div>
            {successfulData.items.length === 0 ? (
              <div className={styles.state}>
                {successfulData.total > 0 ? <CircleHelp size={28} aria-hidden="true" /> : <Bell size={28} aria-hidden="true" />}
                <h3>{successfulData.total > 0 ? '当前页没有记录' : filtered ? '没有匹配的告警' : '暂无告警'}</h3>
                <p>{successfulData.total > 0 ? '当前页未返回记录，请回到第一页查看。' : filtered ? '可以调整时间、关键词、严重性或当前状态筛选。' : '当前没有告警记录。'}</p>
                {successfulData.total > 0 && <Button onClick={() => navigate({ ...filters, page: 1 })}>回到第一页</Button>}
                {successfulData.total === 0 && filtered && <Button onClick={() => navigate({ page: 1, pageSize: filters.pageSize })}>清除筛选</Button>}
              </div>
            ) : (
              <>
                <div className={styles.desktopTable}>
                  <table className={styles.table} aria-label="告警记录">
                    <thead><tr>
                      <th className={styles.severityColumn} scope="col">严重性</th><th scope="col">告警标题 / 编号</th>
                      <th className={styles.timeColumn} scope="col">创建时间（UTC+8）</th>
                      <th className={styles.eventsColumn} scope="col">关联事件</th><th className={styles.statusColumn} scope="col">当前状态</th>
                    </tr></thead>
                    <tbody>{successfulData.items.map((alert) => (
                      <tr key={alert.alert_id}>
                        <td><SeverityLabel severity={alert.severity} /></td>
                        <td><Link className={styles.alertTitle} href={detailHref(alert.alert_id)}>{alert.title}</Link><span className={styles.alertId}>{alert.alert_id}</span></td>
                        <td><CreatedTime alert={alert} /></td><td>{alert.event_ids.length} 个事件</td><td>{statusLabels[alert.status]}</td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
                <ul className={styles.cards} aria-label="告警卡片">
                  {successfulData.items.map((alert) => (
                    <li key={alert.alert_id} className={styles.card}>
                      <div className={styles.cardStatus}><SeverityLabel severity={alert.severity} /><span>{statusLabels[alert.status]}</span></div>
                      <h3><Link className={styles.alertTitle} href={detailHref(alert.alert_id)}>{alert.title}</Link></h3><p className={styles.alertId}>{alert.alert_id}</p>
                      <dl><div><dt>创建时间（UTC+8）</dt><dd><CreatedTime alert={alert} /></dd></div>
                        <div><dt>关联事件</dt><dd>{alert.event_ids.length} 个事件</dd></div></dl>
                    </li>
                  ))}
                </ul>
              </>
            )}
            <footer className={styles.pagination}>
              <span>第 {successfulData.page} 页 · 每页 {successfulData.page_size} 条</span>
              <div className={styles.pageButtons}>
                <Button disabled={filters.page <= 1} onClick={() => navigate({ ...filters, page: filters.page - 1 })}>上一页</Button>
                <Button disabled={filters.page * filters.pageSize >= successfulData.total} onClick={() => navigate({ ...filters, page: filters.page + 1 })}>下一页</Button>
              </div>
            </footer>
          </>
        ) : null}
      </section>
    </div>
  );
}
