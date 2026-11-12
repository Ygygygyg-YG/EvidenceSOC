import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:3000';
const port = new URL(baseURL).port || '3000';
const isolatedBackend = process.env.TASK10_LIVE_ISOLATED_BACKEND;
const webMode = process.env.PLAYWRIGHT_WEB_MODE ?? 'dev';

if (!['dev', 'production'].includes(webMode)) {
  throw new Error('PLAYWRIGHT_WEB_MODE must be dev or production.');
}

if (isolatedBackend && process.env.BACKEND_URL !== isolatedBackend) {
  throw new Error('BACKEND_URL must exactly match TASK10_LIVE_ISOLATED_BACKEND for real browser acceptance.');
}

export default defineConfig({
  testDir: './e2e',
  testIgnore: ['**/ui-p2.spec.ts', '**/ui-p3.spec.ts', '**/ui-p4.spec.ts'],
  workers: 1,
  fullyParallel: false,
  retries: 0,
  use: {
    baseURL,
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    // The acceptance runner builds successfully before selecting production.
    command: `pnpm ${webMode === 'production' ? 'start' : 'dev'} --port ${port}`,
    url: baseURL,
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      FRONTEND_ORIGIN: new URL(baseURL).origin,
      ...(isolatedBackend ? { BACKEND_URL: isolatedBackend } : {}),
    },
  },
});
