import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:3000';
const port = new URL(baseURL).port || '3000';
const isolatedBackend = process.env.TASK10_LIVE_ISOLATED_BACKEND;

if (isolatedBackend && process.env.BACKEND_URL !== isolatedBackend) {
  throw new Error('BACKEND_URL must exactly match TASK10_LIVE_ISOLATED_BACKEND for real browser acceptance.');
}

export default defineConfig({
  testDir: './e2e',
  use: {
    baseURL,
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: `pnpm dev --port ${port}`,
    url: baseURL,
    reuseExistingServer: !process.env.CI && !isolatedBackend,
    env: {
      FRONTEND_ORIGIN: new URL(baseURL).origin,
      ...(isolatedBackend ? { BACKEND_URL: isolatedBackend } : {}),
    },
  },
});
