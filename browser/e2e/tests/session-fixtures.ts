import { constants } from 'node:fs';
import { cp, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { test as base, expect, installEmptyDiscoveryRoom } from './fixtures';
import type { BrowserContext, Page, TestInfo } from '@playwright/test';
import {
  before as freshBefore,
  devDrive,
  FRONTEND_URL,
  installCommitWatcher,
  waitForSynced,
} from './test-utils';
import {
  registerPerfPage,
  applyCpuThrottle,
  envCpuThrottle,
} from './perf-attach';

export * from './fixtures';

type Seed = { directory: string; url: string };
const clonedContexts = new WeakMap<BrowserContext, Seed>();

/**
 * Opt-in for drive-scoped UI specs only. Authentication, personal-drive,
 * account settings, discovery, backup and cold-storage specs use fresh contexts.
 * A worker owns one immutable CLOSED profile; every test copies it, including
 * OPFS and IndexedDB CryptoKeys, then creates its own project drive.
 */
export const test = base.extend<{}, { sessionSeed: Seed | undefined }>({
  sessionSeed: [
    async ({ playwright, browserName, launchOptions }, use, workerInfo) => {
      if (process.env.ATOMIC_E2E_CLONE_SESSION !== '1') {
        await use(undefined);

        return;
      }

      const browserType = playwright[browserName];

      if (browserName !== 'chromium')
        throw new Error(
          'Cloned session experiment currently requires Chromium',
        );

      const seeds = join(workerInfo.project.outputDir, 'session-seeds');
      await mkdir(seeds, { recursive: true });
      const directory = await mkdtemp(join(seeds, 'worker-'));
      let context: BrowserContext | undefined;

      try {
        context = await browserType.launchPersistentContext(directory, {
          ...launchOptions,
          headless: true,
        });
        const diagnostics: string[] = [];
        context.on('console', message => {
          if (['warning', 'error'].includes(message.type()))
            diagnostics.push(message.text());
        });

        const watchPage = (page: Page) => {
          page.on('pageerror', error => diagnostics.push(error.message));
        };

        context.pages().forEach(watchPage);
        context.on('page', watchPage);
        await installEmptyDiscoveryRoom(context);
        await context.addInitScript(origin => {
          if (location.origin !== origin) return;
          localStorage.setItem('viewTransitionsDisabled', 'true');
        }, new URL(FRONTEND_URL).origin);
        const page = context.pages()[0] ?? (await context.newPage());
        await devDrive(page);
        await waitForSynced(page);
        await page.evaluate(async () => {
          await window.store!.getClientDb()!.flush();
        });
        const url = page.url();
        // Stop workers and close every database before copying. Copying a live
        // OPFS/redb file can produce a torn image even after an explicit flush.
        await context.close();
        expect(diagnostics, 'Seed initialization diagnostics').toEqual([]);

        await use({ directory, url });
      } finally {
        await context?.close();
        await rm(directory, { recursive: true, force: true });
      }
    },
    { scope: 'worker', timeout: 60_000 },
  ],
  context: async (
    {
      context: freshContext,
      sessionSeed,
      playwright,
      browserName,
      launchOptions,
      viewport,
      locale,
      timezoneId,
      userAgent,
      deviceScaleFactor,
      isMobile,
      hasTouch,
      colorScheme,
      contextOptions,
    },
    use,
    testInfo,
  ) => {
    if (!sessionSeed) {
      await use(freshContext);

      return;
    }

    const browserType = playwright[browserName];
    const directory = testInfo.outputPath('browser-profile');
    let context: BrowserContext | undefined;

    try {
      context =
        await test.step('Restore isolated browser profile', async () => {
          // FICLONE asks for copy-on-write where supported, with an ordinary copy
          // fallback. Never hard-link writable browser database files.
          await cp(sessionSeed.directory, directory, {
            recursive: true,
            mode: constants.COPYFILE_FICLONE,
          });
          const clone = await browserType.launchPersistentContext(directory, {
            ...launchOptions,
            ...contextOptions,
            viewport,
            locale,
            timezoneId,
            userAgent,
            deviceScaleFactor,
            isMobile,
            hasTouch,
            colorScheme,
          });
          const deviceId = randomUUID();
          await clone.addInitScript(
            ({ id, origin }) => {
              if (location.origin !== origin) return;
              // Stable within this clone, distinct from the seed and every sibling.
              localStorage.setItem('atomic-device-id', id);
            },
            { id: deviceId, origin: new URL(sessionSeed.url).origin },
          );
          clonedContexts.set(clone, sessionSeed);

          return clone;
        });
      await use(context);
    } finally {
      await context?.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
  page: async ({ context }, use) => {
    // Persistent Chromium starts with a blank tab; avoid opening a second one.
    await use(context.pages()[0] ?? (await context.newPage()));
  },
});

export async function before(
  { page }: { page: Page },
  testInfo: TestInfo = test.info(),
) {
  const seed = clonedContexts.get(page.context());

  if (!seed) return freshBefore({ page }, testInfo);

  registerPerfPage(testInfo, page);
  const throttle = envCpuThrottle();
  if (throttle) await applyCpuThrottle(page, throttle);
  await installCommitWatcher(page);
  await test.step('Initialize fresh drive from cloned session', async () => {
    await page.goto(seed.url);
    await page.waitForFunction(
      () => window.store?.getAgent() && window.store.getClientDb()?.isReady,
    );
    const subject = await page.evaluate(async () => {
      const store = window.store!;
      const drive = await store.createDrive('Test drive', { personal: false });
      store.setDrive(drive.subject);

      return drive.subject;
    });
    await page.waitForFunction(
      expectedDrive => window.store?.getDrive() === expectedDrive,
      subject,
    );
    await page.goto(
      new URL(`/app/show?subject=${encodeURIComponent(subject)}`, seed.url)
        .href,
    );
    await expect(
      page
        .getByRole('main')
        .getByRole('heading', { name: 'Test drive', exact: true }),
    ).toBeVisible();
  });
}
