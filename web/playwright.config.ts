import { defineConfig, devices } from '@playwright/test';
import { E2E } from './e2e/env';

export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  globalSetup: './e2e/global-setup.ts',
  // Every sign-in revokes that account's other sessions (admin is shared
  // across specs), so tests must not run concurrently.
  workers: 1,
  use: { baseURL: E2E.baseURL, trace: 'retain-on-failure', acceptDownloads: true, ignoreHTTPSErrors: true },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 900 },
        // The server and the browser must use the same issuer URL
        // (http://dex:5556/dex); resolve the compose name to the host port.
        launchOptions: { args: ['--host-resolver-rules=MAP dex 127.0.0.1'] },
      },
    },
  ],
});
