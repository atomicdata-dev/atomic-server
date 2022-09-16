import { PlaywrightTestConfig } from "@playwright/test";

const config: PlaywrightTestConfig = {
  use: {
    screenshot: "only-on-failure",
    viewport: { width: 1200, height: 800 },
  },
  fullyParallel: true,
};
export default config;
