import { createRequire } from 'node:module';
import path from 'node:path';
import type { Route } from '@playwright/test';

export type FixtureAudit = { writes: string[]; unknown: string[] };

const webRequire = createRequire(path.resolve(__dirname, '../../package.json'));
type FixturePage = { alerts: unknown[]; health: unknown; incidents: unknown[]; plans: unknown[];
  summary: (window?: string) => unknown; page: (items: unknown[], url: URL) => unknown };
const fixture = webRequire(path.resolve(__dirname, 'p2-fixtures.cjs')) as FixturePage;

export async function routeReadOnly(route: Route, audit: FixtureAudit) {
  const request = route.request(); const method = request.method(); const url = new URL(request.url());
  if (!['GET', 'HEAD'].includes(method)) { audit.writes.push(`${method} ${url.pathname}`); await route.fulfill({ status: 405, json: { error: { code: 'UI_WRITES_FORBIDDEN', message: 'Visual read-only fixture', trace_id: 'UI-ROUTE' } } }); return; }
  if (url.pathname === '/api/v1/dashboard/summary') { await route.fulfill({ json: fixture.summary(url.searchParams.get('window') ?? '24h') }); return; }
  if (url.pathname === '/api/v1/data-sources/health') { await route.fulfill({ json: fixture.health }); return; }
  if (url.pathname === '/api/v1/alerts') { await route.fulfill({ json: fixture.page(fixture.alerts, url) }); return; }
  if (url.pathname === '/api/v1/incidents') { await route.fulfill({ json: fixture.page(fixture.incidents, url) }); return; }
  if (url.pathname === '/api/v1/response-plans') { await route.fulfill({ json: fixture.page(fixture.plans, url) }); return; }
  if (url.pathname === '/api/v1/session' || url.pathname === '/api/v1/session/demo') { await route.fulfill({ status: 401, json: { error: { code: 'UNAUTHORIZED', message: 'Visual fixture has no identity', trace_id: 'UI-SESSION' } } }); return; }
  audit.unknown.push(`${method} ${url.pathname}`); await route.fulfill({ status: 404, json: { error: { code: 'UI_FIXTURE_NOT_FOUND', message: 'Visual route not provided', trace_id: 'UI-UNKNOWN' } } });
}
