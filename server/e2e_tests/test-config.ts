import { TestConfig } from "./e2e-generated.spec";
const demoFileName = 'testimage.svg';

export const testConfig: TestConfig = {
  demoFileName,
  demoFile: `./${demoFileName}`,
  demoInviteName: 'document demo',
  serverUrl: 'http://localhost:9883',
  frontEndUrl: 'http://localhost:9883',
  initialTest: true,
};
