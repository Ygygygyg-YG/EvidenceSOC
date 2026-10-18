import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => { vi.unstubAllEnvs(); vi.resetModules(); });

async function config(mode?: string) {
  if (mode !== undefined) vi.stubEnv('PLAYWRIGHT_WEB_MODE', mode);
  vi.stubEnv('PLAYWRIGHT_BASE_URL', 'http://127.0.0.1:3018');
  vi.stubEnv('TASK10_LIVE_ISOLATED_BACKEND', '');
  vi.stubEnv('CI', '');
  vi.resetModules();
  return (await import('../../../playwright.config')).default;
}

describe('browser server lifecycle', () => {
  it('starts the built production server without reusing another process', async () => {
    const actual = await config('production');
    expect(actual.webServer).toMatchObject({ command: 'pnpm start --port 3018', reuseExistingServer: false });
    expect(actual.workers).toBe(1);
    expect(actual.retries).toBe(0);
  });

  it('retains the dev server when explicitly selected', async () => {
    const actual = await config('dev');
    expect(actual.webServer).toMatchObject({ command: 'pnpm dev --port 3018', reuseExistingServer: false });
  });

  it('rejects an unknown server mode instead of falling back', async () => {
    await expect(config('prodution')).rejects.toThrow('PLAYWRIGHT_WEB_MODE');
  });

  it('fails before launch when the real proxy points at another backend', async () => {
    vi.stubEnv('TASK10_LIVE_ISOLATED_BACKEND', 'http://127.0.0.1:8018');
    vi.stubEnv('BACKEND_URL', 'http://127.0.0.1:8000');
    await expect(import('../../../playwright.config')).rejects.toThrow('BACKEND_URL');
  });
});
