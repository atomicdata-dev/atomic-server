import type { PlaywrightTestConfig } from '@playwright/test';
import { devices } from '@playwright/test';

const config: PlaywrightTestConfig = {
  use: {
    screenshot: 'only-on-failure',
    viewport: { width: 1200, height: 800 },
  },
  retries: 3,
  timeout: 1000 * 120, // 2 minutes
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  // projects: [
  //   {
  //     name: 'chromium',
  //     use: { ...devices['Desktop Chrome'] },
  //   },
  //   {
  //     name: 'firefox',
  //     use: { ...devices['Desktop Firefox'] },
  //   },
  //   {
  //     name: 'webkit',
  //     use: { ...devices['Desktop Safari'] },
  //   },
  // ],
  fullyParallel: true,
};

export default config;
