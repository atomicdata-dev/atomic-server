import type { Page } from '@playwright/test';
import { FRONTEND_URL } from './test-utils';

/** Explicitly opt into the hosted app; localhost by itself is standalone.
 * Endpoint-specific mocks registered afterwards override this empty account API.
 * Using the test origin also keeps the fixture independent of a local portal.
 */
export async function mockManagedPortal(page: Page): Promise<void> {
  await page.addInitScript(portalUrl => {
    (
      window as unknown as Window & {
        __ATOMIC_MANAGED__: { portalUrl: string };
      }
    ).__ATOMIC_MANAGED__ = { portalUrl };
  }, new URL(FRONTEND_URL).origin);
  await page.route('**/api/**', route => route.fulfill({ json: [] }));
}
