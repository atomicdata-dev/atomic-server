import { test, expect } from '@playwright/test';
import { devDrive, FRONTEND_URL } from './test-utils';

for (const localOnly of [true, false]) {
  test(`managed sync keeps server state honest (localOnly=${localOnly})`, async ({
    page,
  }) => {
    await devDrive(page);
    await page.route('**/api/me', route =>
      route.fulfill({ json: { email: 'sync-test@example.com' } }),
    );
    await page.route('**/api/sync-enrollments', route =>
      route.fulfill({ json: [] }),
    );
    await page.route('**/api/recovery-secret', route =>
      route.fulfill({ status: 204 }),
    );

    const attachment = localOnly
      ? null
      : await page.evaluate(async () => {
          const store = window.store;
          const [subject] = await store.uploadFiles(
            [
              new File(['Keep these attachment bytes'], 'migration.txt', {
                type: 'text/plain',
              }),
            ],
            store.getDrive()!,
          );

          return subject;
        });

    if (localOnly) {
      const drive = await page.evaluate(() => window.store.getDrive());
      const enrollment = {
        id: 'vault-test',
        drive_subject: drive,
        drive_pseudonym: 'vault-test',
        status: 'active',
        used_bytes: 453000,
        quota_bytes: 5000000000,
        last_backup_at: Date.now(),
      };
      await page.route('**/api/cloud-vault/drives', route =>
        route.fulfill({ json: [enrollment] }),
      );
      await page.route('**/api/cloud-vault/vault-test/state', route =>
        route.fulfill({
          json: {
            enrollment,
            lanes: {},
            checkpoints: [],
            pending_uploads: 0,
            confirmed_objects: 59,
          },
        }),
      );
      await page.evaluate(() =>
        window.store.registerLocalOnlyDrive(window.store.getDrive()!),
      );
    }

    const writes: string[] = [];
    let switched = false;
    page.on('request', request => {
      if (switched && new URL(request.url()).pathname === '/commit')
        writes.push('HTTP commit');
    });
    page.on('websocket', socket =>
      socket.on('framesent', ({ payload }) => {
        if (
          switched &&
          Buffer.isBuffer(payload) &&
          [0x13, 0x33].includes(payload[0])
        )
          writes.push('WebSocket mutation');
      }),
    );

    await page.goto(`${FRONTEND_URL}/app/sync`);
    await expect(
      page.getByRole('heading', { name: 'Sync', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('heading', { name: 'Sync a device', exact: true }),
    ).toHaveCount(0);

    if (localOnly) {
      await expect(
        page.getByText(
          'Cloud Vault is on; browser sync connects your open devices.',
          { exact: false },
        ),
      ).toBeVisible();
      await expect(
        page.getByRole('button', { name: 'Switch', exact: true }),
      ).toHaveCount(0);
    } else {
      await expect(
        page.getByText(
          'Your account session has ended. Sign in again to resume backup.',
          { exact: true },
        ),
      ).toBeVisible();
      await expect(
        page.getByText('Invalid hook call.', { exact: false }),
      ).toHaveCount(0);

      await expect(
        page.getByText(
          'This drive is still syncing with a server, but Cloud Server hosting has not been confirmed.',
          { exact: true },
        ),
      ).toBeVisible();
      await page.waitForFunction(() => {
        const status = window.store.getSyncStatus();

        return !status.syncInProgress && !status.pendingDirtyCount;
      });

      // A failed local read must keep the existing connection and routing.
      const refused = await page.evaluate(async () => {
        const store = window.store;
        const db = store.getClientDb()!;
        const read = db.getResourceWithSnapshot;
        db.getResourceWithSnapshot = async () => ({
          jsonAd: null,
          snapshot: null,
        });

        try {
          await store.makeDriveLocal(store.getDrive()!);

          return {
            error: '',
            local: store.isLocalOnlyDrive(store.getDrive()!),
          };
        } catch (error) {
          return {
            error: String(error),
            local: store.isLocalOnlyDrive(store.getDrive()!),
          };
        } finally {
          db.getResourceWithSnapshot = read;
        }
      });
      expect(refused.error).toContain('missing its local history');
      expect(refused.local).toBe(false);

      await page
        .getByRole('button', {
          name: 'Use browser sync only on this device',
          exact: true,
        })
        .click();
      await page.waitForFunction(() =>
        window.store.isLocalOnlyDrive(window.store.getDrive()!),
      );
      switched = true;
      await page.evaluate(async () => {
        const store = window.store;
        const drive = await store.getResource(store.getDrive()!);
        await drive.set(
          'https://atomicdata.dev/properties/description',
          'Saved after switching to browser sync',
        );
        await drive.save();
        await store.getClientDb()!.flush();
      });
      await page.reload();
      await expect(
        page.getByText(
          'Browser sync connects when another browser is available.',
          { exact: false },
        ),
      ).toBeVisible();
      const persisted = await page.evaluate(async subject => {
        const store = window.store;
        const drive = await store.getResource(store.getDrive()!);
        const file = await store.getResource(subject!);
        const blob = file.get(
          'https://atomicdata.dev/properties/blob',
        ) as string;
        const hash = Uint8Array.from(
          blob.slice('did:ad:blob:'.length).match(/../g)!,
          part => parseInt(part, 16),
        );
        const bytes = await store.getClientDb()!.getBlob(hash);

        return {
          description: drive.get(
            'https://atomicdata.dev/properties/description',
          ),
          attachment: new TextDecoder().decode(bytes!),
        };
      }, attachment);
      expect(persisted).toEqual({
        description: 'Saved after switching to browser sync',
        attachment: 'Keep these attachment bytes',
      });
      expect(writes).toEqual([]);
    }
  });
}
