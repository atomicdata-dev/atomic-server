import { test as base, expect } from './fixtures';
import { mockManagedPortal } from './managed-test-utils';
import { devDrive } from './test-utils';

/** Declare deployment behavior independently of the host/port under test. */
type DeploymentFixtures = {
  deployment: 'standalone' | 'managed';
};

export const standaloneTest: ReturnType<
  typeof base.extend<DeploymentFixtures>
> = base.extend<DeploymentFixtures>({
  deployment: ['standalone', { option: true }],
  page: async ({ page, deployment }, use) => {
    if (deployment === 'managed') {
      await mockManagedPortal(page);
    }

    await use(page);
  },
});

export const managedTest: typeof standaloneTest = standaloneTest.extend({
  deployment: 'managed',
});
/** Create an identity before entering mocked hosted mode. The dev-drive route
 * is a standalone development entry point, not hosted onboarding.
 */
export const managedDriveTest: typeof standaloneTest = standaloneTest.extend({
  page: async ({ page }, use) => {
    await devDrive(page);
    await mockManagedPortal(page);
    await use(page);
  },
});
export { expect };
