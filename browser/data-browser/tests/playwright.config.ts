import type { PlaywrightTestConfig } from '@playwright/test';
import { devices } from '@playwright/test';

const config: PlaywrightTestConfig = {
  use: {
    screenshot: 'only-on-failure',
    viewport: { width: 1200, height: 800 },
    locale: 'en-GB',
    timezoneId: 'Europe/Amsterdam',
    actionTimeout: 5000,
  },
  reporter: [['html', { attachmentsBaseURL: 'https://external-storage.com/' }]],
  retries: 3,
  // timeout: 1000 * 120, // 2 minutes
  projects: [
    {
      name: 'setup',
      testMatch: /global.setup\.ts/,
    },
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
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
