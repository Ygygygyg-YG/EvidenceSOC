'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Button, Select } from 'antd';
import { AlertCircle, CircleHelp, LoaderCircle, Search } from 'lucide-react';
import { resolveShanghaiDateTimeInput, severityLabels, statusLabels, statusValues,
  toShanghaiDateTimeInput, type IncidentStatus } from '../alerts/alertsContract';
import {
  buildIncidentsQuery, incidentDetailHref, IncidentsRequestError, loadIncidents, pageSizeOptions,
  readIncidentFilters, validationOutcomeLabels, type IncidentFilters, type IncidentListItem,
} from './incidentsListContract';
import styles from './IncidentsList.module.css';

const dateFormatter = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
});

function CreatedTime({ value }: { value: string }) {
  return <time dateTime={value} title={value}>{dateFormatter.format(new Date(value))}</time>;
}

function Validation({ incident }: { incident: IncidentListItem }) {
  return <>{incident.validation_outcome ? validationOutcomeLabels[incident.validation_outcome] : '尚无验证结果'}</>;
}

function TimeFilters({ filters, navigate }: { filters: IncidentFilters; navigate: (next: IncidentFilters) => void }) {
  const [from, setFrom] = useState(filters.timeFrom ? toShanghaiDateTimeInput(filters.timeFrom) : '');
  const [to, setTo] = useState(filters.timeTo ? toShanghaiDateTimeInput(filters.timeTo) : '');
  const [invalid, setInvalid] = useState(false);
  const apply = () => {
    const timeFrom = resolveShanghaiDateTimeInput(from, filters.timeFrom);
    const timeTo = resolveShanghaiDateTimeInput(to, filters.timeTo);
    if (!timeFrom || !timeTo || Date.parse(timeFrom) >= Date.parse(timeTo)) { setInvalid(true); return; }
    setInvalid(false);
    navigate({ ...filters, timeFrom, timeTo, page: 1 });
  };
  return <>
    <label className={styles.filter} htmlFor="incidents-time-from"><span>开始时间（UTC+8）</span>
      <input id="incidents-time-from" className={styles.timeInput} type="datetime-local" step={1} value={from}
        onChange={(event) => { setFrom(event.target.value); setInvalid(false); }} />
    </label>
    <label className={styles.filter} htmlFor="incidents-time-to"><span>结束时间（UTC+8）</span>
      <input id="incidents-time-to" className={styles.timeInput} type="datetime-local" step={1} value={to}
        onChange={(event) => { setTo(event.target.value); setInvalid(false); }} />
    </label>
    <div className={styles.timeActions}>
      <Button onClick={apply}>应用时间</Button>
      <Button onClick={() => { setFrom(''); setTo(''); setInvalid(false);
        navigate({ ...filters, timeFrom: undefined, timeTo: undefined, page: 1 }); }}>清除时间</Button>
    </div>
    {invalid && <p className={styles.filterError} role="alert">请选择有效的开始和结束时间，结束时间必须晚于开始时间。</p>}
  </>;
}

export default function IncidentsList() {
  const router = useRouter();
  const params = useSearchParams();
  const filters = readIncidentFilters(params);
  const queryString = buildIncidentsQuery(filters);
  const query = useQuery({ queryKey: ['incidents', queryString], queryFn: ({ signal }) => loadIncidents(filters, signal), retry: false, staleTime: 0 });
  const navigate = (next: IncidentFilters) => router.push(`/incidents?${buildIncidentsQuery(next)}`, { scroll: false });
  const data = query.data;
  const error = query.error instanceof IncidentsRequestError ? query.error : null;
  const loading = !data && (query.isPending || query.isFetching);

  return <div className={styles.page}>
    <header className={styles.header}><h1>调查列表</h1><p>查看真实案件状态、证据数量和验证结论。</p></header>
    <section className={styles.panel} aria-label="案件工作区">
      <div className={styles.filters}>
        <label className={styles.filter} htmlFor="incidents-status"><span>当前状态</span>
          <Select<IncidentStatus | 'all'> id="incidents-status" aria-label="当前状态" virtual={false}
            value={filters.status ?? 'all'}
            options={[{ value: 'all', label: '全部状态' }, ...statusValues.map((value) => ({ value, label: statusLabels[value] }))]}
            onChange={(status) => navigate({ ...filters, status: status === 'all' ? undefined : status, page: 1 })} />
        </label>
        <label className={styles.filter} htmlFor="incidents-risk"><span>告警风险</span>
          <Select<'all' | 'high'> id="incidents-risk" aria-label="告警风险" virtual={false}
            value={filters.risk ?? 'all'} options={[{ value: 'all', label: '全部风险' }, { value: 'high', label: '高危及严重' }]}
            onChange={(risk) => navigate({ ...filters, risk: risk === 'all' ? undefined : risk, page: 1 })} />
        </label>
        <TimeFilters key={`${filters.timeFrom ?? ''}:${filters.timeTo ?? ''}`} filters={filters} navigate={navigate} />
        <label className={styles.filter} htmlFor="incidents-page-size"><span>每页条数</span>
          <Select<number> id="incidents-page-size" aria-label="每页条数" virtual={false}
            value={filters.pageSize} options={pageSizeOptions.map((value) => ({ value, label: `${value} 条/页` }))}
            onChange={(pageSize) => navigate({ ...filters, pageSize, page: 1 })} />
        </label>
      </div>
      <p className={styles.statusNote}>时间区间按案件创建时间筛选，包含开始、不包含结束。高危及严重按关联告警级别筛选。</p>
      {filters.timeFrom && filters.timeTo && <p className={styles.scopeNote}>当前时间范围（UTC+8）：<CreatedTime value={filters.timeFrom} /> 至 <CreatedTime value={filters.timeTo} /></p>}
      {loading ? <div className={styles.state} role="status"><LoaderCircle size={26} aria-hidden="true" /><p>正在加载案件…</p></div>
        : !data && query.isError ? <div className={styles.state} role="alert">
          <AlertCircle size={26} aria-hidden="true" /><h2>案件加载失败</h2>
          <p>{error?.message ?? '案件请求失败，请重试。'}</p>
          {error && <p className={styles.meta}>错误代码：{error.code}</p>}
          {error?.traceId && <p className={styles.meta}>Trace ID：<code>{error.traceId}</code></p>}
          <Button autoInsertSpace={false} onClick={() => { void query.refetch(); }}>重试</Button>
        </div> : data ? <>
          {query.isFetching ? <div className={styles.notice} role="status">正在更新，展示上次成功结果。</div>
            : query.isError ? <div className={styles.notice} role="alert">
              <p>更新失败，展示上次成功结果。{error?.message ?? ''}</p>
              {error?.traceId && <p>Trace ID：<code>{error.traceId}</code></p>}
              <Button autoInsertSpace={false} onClick={() => { void query.refetch(); }}>重试</Button>
            </div> : null}
          <div className={styles.summary}><h2>案件记录</h2><div>
            <span data-testid="incidents-total">共 {data.total} 条案件</span>
            <Button autoInsertSpace={false} loading={query.isFetching} onClick={() => { void query.refetch(); }}>刷新</Button>
          </div></div>
          {data.items.length === 0 ? <div className={styles.state}>
            {data.total > 0 ? <CircleHelp size={26} aria-hidden="true" /> : <Search size={26} aria-hidden="true" />}
            <h2>{data.total > 0 ? '当前页没有案件' : filters.status || filters.risk || filters.timeFrom ? '没有匹配的案件' : '暂无案件'}</h2>
            <p>{data.total > 0 ? '请回到第一页查看。' : filters.status || filters.risk || filters.timeFrom ? '可以更换筛选条件。' : '当前没有案件记录。'}</p>
            {data.total > 0 && <Button onClick={() => navigate({ ...filters, page: 1 })}>回到第一页</Button>}
            {data.total === 0 && (filters.status || filters.risk || filters.timeFrom) && <Button onClick={() => navigate({ page: 1, pageSize: filters.pageSize })}>清除筛选</Button>}
          </div> : <>
            <div className={styles.tableScroller}><table className={styles.table} aria-label="案件记录">
              <thead><tr><th scope="col">案件 / 调查编号</th><th scope="col">告警</th><th scope="col">当前状态</th><th scope="col">证据</th><th scope="col">验证结论</th><th scope="col">创建时间（UTC+8）</th></tr></thead>
              <tbody>{data.items.map((incident) => <tr key={incident.incident_id}>
                <td><Link href={incidentDetailHref(incident.incident_id, filters)}>{incident.incident_id}</Link>
                  <span className={styles.id}>{incident.investigation_id ?? '尚无调查编号'}</span></td>
                <td><Link href={`/alerts/${encodeURIComponent(incident.alert_id)}`}>{incident.alert_title}</Link>
                  <span className={styles.id}>{severityLabels[incident.severity]}</span></td>
                <td>{statusLabels[incident.status]}</td><td>{incident.evidence_count} 条</td>
                <td><Validation incident={incident} /></td><td><CreatedTime value={incident.created_at} /></td>
              </tr>)}</tbody>
            </table></div>
            <ul className={styles.cards} aria-label="案件卡片">{data.items.map((incident) => <li key={incident.incident_id}>
              <Link href={incidentDetailHref(incident.incident_id, filters)}>{incident.incident_id}</Link>
              <p>{incident.alert_title}</p><span>{statusLabels[incident.status]} · {incident.evidence_count} 条证据</span>
              <span><Validation incident={incident} /></span>
            </li>)}</ul>
          </>}
          <footer className={styles.pagination}><span>第 {data.page} 页 · 每页 {data.page_size} 条</span>
            <div><Button disabled={filters.page <= 1} onClick={() => navigate({ ...filters, page: filters.page - 1 })}>上一页</Button>
              <Button disabled={filters.page * filters.pageSize >= data.total} onClick={() => navigate({ ...filters, page: filters.page + 1 })}>下一页</Button></div>
          </footer>
        </> : null}
    </section>
  </div>;
}
