import { PlaywrightTestConfig } from '@playwright/test';

const config: PlaywrightTestConfig = {
  use: { screenshot: 'only-on-failure' },
  fullyParallel: true,
};
export default config;
