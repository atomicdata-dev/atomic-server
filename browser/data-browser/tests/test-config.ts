import type { TestConfig } from './e2e.spec.js';
const demoFileName = 'testimage.svg';

export const testConfig: TestConfig = {
  demoFileName,
  demoFile: `${process.cwd()}/tests/${demoFileName}`,
  demoInviteName: 'document demo',
  serverUrl: process.env.SERVER_URL || 'http://localhost:9883',
  frontEndUrl: 'http://localhost:5173',
  initialTest: false,
};
