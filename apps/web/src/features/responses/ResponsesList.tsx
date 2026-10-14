'use client';

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Button, Select } from 'antd';
import { AlertCircle, CircleHelp, LoaderCircle, ShieldCheck } from 'lucide-react';
import { severityLabels, statusLabels } from '../alerts/alertsContract';
import {
  buildResponseQuery, decisionFilters, loadResponsePlans, pageSizeOptions, readResponseFilters,
  ResponsePlanRequestError, type DecisionFilter, type DecisionState, type ResponseFilters,
} from './responseContract';
import styles from './ResponsesList.module.css';

const dateFormatter = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
});
const filterLabels: Record<DecisionFilter, string> = { pending: '待处理', approved: '已批准', rejected: '已拒绝' };
export const decisionStateLabels: Record<DecisionState, string> = {
  pending: '待处理', submitting: '提交中', approved: '已批准', rejected: '已拒绝',
};
const riskNames = { low: '低', medium: '中', high: '高', critical: '严重' } as const;

export default function ResponsesList() {
  const router = useRouter();
  const params = useSearchParams();
  const filters = readResponseFilters(params);
  const queryString = buildResponseQuery(filters);
  const query = useQuery({
    queryKey: ['response-plans', queryString], queryFn: ({ signal }) => loadResponsePlans(filters, signal),
    retry: false, staleTime: 0,
  });
  const navigate = (next: ResponseFilters) => router.push(`/responses?${buildResponseQuery(next)}`, { scroll: false });
  const detailHref = (id: string) => `/responses/${encodeURIComponent(id)}?from=${encodeURIComponent(queryString)}`;
  const data = query.data;
  const error = query.error instanceof ResponsePlanRequestError ? query.error : null;
  const loading = !data && (query.isPending || query.isFetching);

  return <div className={styles.page}>
    <header className={styles.header}>
      <div><h1>响应审批</h1><p>审查响应方案及其模拟动作，再记录人工决定。</p></div>
      <span className={styles.simulation}>仅模拟处置</span>
    </header>
    <section className={styles.panel} aria-label="响应计划队列">
      <div className={styles.filters}>
        <label className={styles.filter} htmlFor="responses-decision-state"><span>决定状态</span>
          <Select<DecisionFilter | 'all'> id="responses-decision-state" aria-label="决定状态" virtual={false}
            value={filters.decisionState ?? 'all'}
            options={[{ value: 'all', label: '全部状态' }, ...decisionFilters.map((value) => ({ value, label: filterLabels[value] }))]}
            onChange={(value) => navigate({ ...filters, decisionState: value === 'all' ? undefined : value, page: 1 })} />
        </label>
        <label className={styles.filter} htmlFor="responses-page-size"><span>每页条数</span>
          <Select<number> id="responses-page-size" aria-label="每页条数" virtual={false}
            value={filters.pageSize} options={pageSizeOptions.map((value) => ({ value, label: `${value} 条/页` }))}
            onChange={(pageSize) => navigate({ ...filters, pageSize, page: 1 })} />
        </label>
      </div>
      <p className={styles.context}>“待处理”包括已提交、尚待服务端记录结果的方案。每条记录的状态均来自服务端。</p>
      {loading ? <div className={styles.state} role="status"><LoaderCircle size={26} aria-hidden="true" /><p>正在加载响应方案…</p></div>
        : !data && query.isError ? <div className={styles.state} role="alert">
          <AlertCircle size={26} aria-hidden="true" /><h2>响应方案加载失败</h2>
          <p>{error?.message ?? '请求失败，请重试。'}</p>
          {error && <p>错误代码：{error.code}</p>}
          {error?.traceId && <p>Trace ID：<code>{error.traceId}</code></p>}
          <Button autoInsertSpace={false} onClick={() => { void query.refetch(); }}>重试</Button>
        </div> : data ? <>
          {query.isFetching ? <div className={styles.notice} role="status">正在更新，展示上次成功结果。</div>
            : query.isError ? <div className={styles.notice} role="alert">
              更新失败，展示上次成功结果。{error?.message ?? ''}
              {error?.traceId && <> Trace ID：<code>{error.traceId}</code></>}
              <Button autoInsertSpace={false} onClick={() => { void query.refetch(); }}>重试</Button>
            </div> : null}
          <div className={styles.summary}><h2>方案记录</h2><div>
            <span data-testid="responses-total">共 {data.total} 个方案</span>
            <Button autoInsertSpace={false} loading={query.isFetching} onClick={() => { void query.refetch(); }}>刷新</Button>
          </div></div>
          {data.items.length === 0 ? <div className={styles.state}>
            {data.total > 0 ? <CircleHelp size={26} aria-hidden="true" /> : <ShieldCheck size={26} aria-hidden="true" />}
            <h2>{data.total > 0 ? '当前页没有方案' : filters.decisionState ? '没有匹配的方案' : '暂无响应方案'}</h2>
            <p>{data.total > 0 ? '请回到第一页查看。' : filters.decisionState ? '可以调整决定状态筛选。' : '调查产生响应方案后会显示在这里。'}</p>
            {data.total > 0 && <Button onClick={() => navigate({ ...filters, page: 1 })}>回到第一页</Button>}
            {data.total === 0 && filters.decisionState && <Button onClick={() => navigate({ page: 1, pageSize: filters.pageSize })}>清除筛选</Button>}
          </div> : <>
            <div className={styles.tableScroller}><table className={styles.table} aria-label="响应方案记录">
              <thead><tr><th scope="col">方案 / 案件</th><th scope="col">关联告警</th><th scope="col">决定状态</th><th scope="col">风险 / 有效期</th><th scope="col">拟模拟动作</th><th scope="col">生成时间（UTC+8）</th></tr></thead>
              <tbody>{data.items.map((plan) => <tr key={plan.response_plan_id}>
                <td><Link href={detailHref(plan.response_plan_id)}>{plan.response_plan_id}</Link>
                  <span className={styles.subline}>{plan.summary}</span><span className={styles.subline}>{plan.incident_id} · 版本 {plan.plan_version.slice(0, 12)}</span></td>
                <td><Link href={`/alerts/${encodeURIComponent(plan.alert_id)}`}>{plan.alert_title}</Link>
                  <span className={styles.subline}>{severityLabels[plan.severity]} · {statusLabels[plan.incident_status]}</span></td>
                <td><span className={styles.status} data-state={plan.decision_state}>{decisionStateLabels[plan.decision_state]}</span>
                  {!plan.is_current && <span className={styles.subline}>历史方案</span>}</td>
                <td>{plan.risk_level ? `${riskNames[plan.risk_level]}风险` : '风险未评估'}
                  <span className={styles.subline}>{plan.is_expired ? '已过期' : plan.expires_at ? `有效至 ${dateFormatter.format(new Date(plan.expires_at))}` : '未设置有效期'}</span></td>
                <td>{plan.actions.length} 项 · 仅模拟</td>
                <td><time dateTime={plan.created_at} title={plan.created_at}>{dateFormatter.format(new Date(plan.created_at))}</time></td>
              </tr>)}</tbody>
            </table></div>
            <ul className={styles.cards} aria-label="响应方案卡片">{data.items.map((plan) => <li key={plan.response_plan_id}>
              <div><span className={styles.status} data-state={plan.decision_state}>{decisionStateLabels[plan.decision_state]}</span><span>{plan.actions.length} 项模拟动作</span></div>
              <h3><Link href={detailHref(plan.response_plan_id)}>{plan.response_plan_id}</Link></h3>
              <p>{plan.summary}</p><small>{plan.alert_title} · {plan.incident_id} · 版本 {plan.plan_version.slice(0, 12)}</small>
              <small>{plan.risk_level ? `${riskNames[plan.risk_level]}风险` : '风险未评估'} · {plan.is_expired ? '已过期' : '有效状态以服务端为准'}</small>
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
