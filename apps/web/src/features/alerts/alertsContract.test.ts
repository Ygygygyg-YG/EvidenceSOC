import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AlertRequestError, alertPageSchema, buildAlertsQuery, changeAlertFilters,
  fromShanghaiDateTimeInput, loadAlerts, readAlertFilters, resolveShanghaiDateTimeInput,
  toShanghaiDateTimeInput, type AlertListItem,
} from './alertsContract';

const record = {
  alert_id: 'AL-test-contract', title: '契约验收告警', severity: 'high',
  created_at: '2026-09-29T02:00:00+00:00', event_ids: ['EVENT-test'], status: 'manual_review',
} satisfies AlertListItem;
const responsePage = { items: [record], total: 41, page: 1, page_size: 20 };

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('告警分页和 URL 契约', () => {
  it('接受当前 OpenAPI 字段，保留真实 total 与调查状态', () => {
    expect(alertPageSchema.parse(responsePage)).toEqual(responsePage);
    expect(alertPageSchema.parse({ items: [], total: 0, page: 1, page_size: 20 }).total).toBe(0);
  });
  it('拒绝未知枚举、缺失状态和不可信的分页总数', () => {
    for (const invalid of [
      { ...responsePage, items: [{ ...record, severity: 'severe' }] },
      { ...responsePage, items: [{ ...record, status: undefined }] },
      { ...responsePage, total: '0' },
      { ...responsePage, total: 0 },
      { ...responsePage, page_size: 201 },
    ]) expect(alertPageSchema.safeParse(invalid).success).toBe(false);
  });
  it('恢复筛选与页码；无效 URL 数值回到 UI 默认值', () => {
    expect(readAlertFilters(new URLSearchParams('page=3&page_size=50&severity=high&status=manual_review')))
      .toEqual({ page: 3, pageSize: 50, severity: 'high', status: 'manual_review' });
    expect(readAlertFilters(new URLSearchParams('page=-1&page_size=999&severity=unknown')))
      .toEqual({ page: 1, pageSize: 20, severity: undefined, status: undefined });
  });
  it('改变筛选或页大小回第一页，全部筛选不写入 query', () => {
    const current = { page: 4, pageSize: 20, severity: 'high' as const, status: 'received' as const };
    expect(changeAlertFilters(current, { severity: 'critical' }).page).toBe(1);
    expect(changeAlertFilters(current, { pageSize: 100 }).page).toBe(1);
    expect(buildAlertsQuery(changeAlertFilters(current, { severity: undefined, status: undefined })))
      .toBe('page=1&page_size=20');
  });
  it('时间窗口与关键词在 URL 中可往返，非法或不完整时间范围不参与筛选', () => {
    const start = '2026-09-30T00:00:00Z';
    const end = '2026-10-01T00:00:00Z';
    const filters = readAlertFilters(new URLSearchParams(`page=3&time_from=${start}&time_to=${end}&query=%20SQL%20`));
    expect(filters).toEqual({ page: 3, pageSize: 20, severity: undefined, status: undefined,
      timeFrom: start, timeTo: end, query: 'SQL' });
    expect(buildAlertsQuery(filters)).toBe(`page=3&page_size=20&time_from=${encodeURIComponent(start)}&time_to=${encodeURIComponent(end)}&query=SQL`);
    expect(changeAlertFilters(filters, { query: '  attack  ' })).toMatchObject({ page: 1, query: 'attack', timeFrom: start, timeTo: end });
    expect(readAlertFilters(new URLSearchParams(`time_from=${end}&time_to=${start}`))).toMatchObject({ timeFrom: undefined, timeTo: undefined });
    expect(readAlertFilters(new URLSearchParams(`time_from=${start}`))).toMatchObject({ timeFrom: undefined, timeTo: undefined });
  });
  it('时间输入明确使用 UTC+8 并保留秒精度', () => {
    expect(toShanghaiDateTimeInput('2026-09-30T00:00:15Z')).toBe('2026-09-30T08:00:15');
    expect(fromShanghaiDateTimeInput('2026-09-30T08:00:15')).toBe('2026-09-30T00:00:15.000Z');
    expect(fromShanghaiDateTimeInput('2026-09-30T08:00')).toBe('2026-09-30T00:00:00.000Z');
    expect(fromShanghaiDateTimeInput('invalid')).toBeUndefined();
  });
  it('未改动的时间输入保留服务端毫秒以上精度', () => {
    const original = '2026-09-30T00:00:00.123456Z';
    expect(resolveShanghaiDateTimeInput('2026-09-30T08:00', original)).toBe(original);
    expect(resolveShanghaiDateTimeInput('2026-09-30T08:01', original)).toBe('2026-09-30T00:01:00.000Z');
  });
});

describe('真实响应读取', () => {
  it('HTTP 错误保留服务端消息与可追踪 ID，不转为空列表', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'DEPENDENCY_UNAVAILABLE', message: 'API dependencies are not ready.', trace_id: null },
    }), { status: 503, headers: { 'x-trace-id': 'TRACE-contract' } })));
    await expect(loadAlerts({ page: 1, pageSize: 20 })).rejects.toMatchObject({
      code: 'DEPENDENCY_UNAVAILABLE', traceId: 'TRACE-contract', status: 503,
    });
  });
  it('错误格式的成功响应与分页错配均不能成为成功数据', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('not-json', { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ...responsePage, page: 2 }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(loadAlerts({ page: 1, pageSize: 20 })).rejects.toBeInstanceOf(AlertRequestError);
    await expect(loadAlerts({ page: 1, pageSize: 20 })).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });
  it('网络失败不伪造数据，请求使用同源路径和调用方取消信号', async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn().mockRejectedValue(new TypeError('offline'));
    vi.stubGlobal('fetch', fetchMock);
    await expect(loadAlerts({ page: 2, pageSize: 50, severity: 'critical' }, controller.signal))
      .rejects.toMatchObject({ code: 'NETWORK_ERROR' });
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/alerts?page=2&page_size=50&severity=critical',
      expect.objectContaining({ signal: controller.signal, cache: 'no-store' }));
  });
  it('后端查询收到精确的时间窗口与关键词', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(responsePage), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    await loadAlerts({ page: 1, pageSize: 20, timeFrom: '2026-09-30T00:00:00Z',
      timeTo: '2026-10-01T00:00:00Z', query: 'SQL' });
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/alerts?page=1&page_size=20&time_from=2026-09-30T00%3A00%3A00Z&time_to=2026-10-01T00%3A00%3A00Z&query=SQL');
  });
});
