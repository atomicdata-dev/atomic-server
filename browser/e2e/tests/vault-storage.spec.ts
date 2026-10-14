import { managedDriveTest as test, expect } from './deployment-fixtures';
import { FRONTEND_URL } from './test-utils';

for (const width of [1200, 390]) {
  test(`Vault usage is distinct from the server copy at ${width}px`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const drive = await page.evaluate(() => window.store.getDrive());
    // This fixture supplies a usage inventory, not encrypted backup bodies.
    // Keep automatic backup/restore out of this presentation-only journey.
    await page.evaluate(subject => {
      localStorage.setItem('atomic.vault.optOut', JSON.stringify([subject]));
    }, drive);
    const enrollment = {
      id: 'storage-test',
      drive_subject: drive,
      drive_pseudonym: 'storage-test',
      status: 'active',
      used_bytes: 91 * 1024 ** 2,
      quota_bytes: 100 * 1024 ** 2,
      last_backup_at: Date.now(),
    };
    await page.route('**/api/me', route =>
      route.fulfill({ json: { email: 'storage-test@example.com' } }),
    );
    await page.route('**/api/sync-enrollments', route =>
      route.fulfill({ json: [] }),
    );
    await page.route('**/api/recovery-secret', route =>
      route.fulfill({ status: 204 }),
    );
    await page.route('**/api/cloud-vault/drives', route =>
      route.fulfill({ json: [enrollment] }),
    );
    await page.route('**/api/cloud-vault/storage-test/state', route =>
      route.fulfill({
        json: {
          enrollment,
          lanes: {},
          checkpoints: [],
          pending_uploads: 0,
          confirmed_objects: 657,
        },
      }),
    );
    await page.route('**/api/cloud-vault/storage-test/usage', route =>
      route.fulfill({
        json: {
          used_bytes: enrollment.used_bytes,
          quota_bytes: enrollment.quota_bytes,
          by_kind: [
            { kind: 'pack', bytes: 59 * 1024 ** 2, objects: 642 },
            { kind: 'checkpoint', bytes: 32 * 1024 ** 2, objects: 15 },
          ],
          pending_bytes: 0,
          unaccounted_bytes: 0,
          reclaimable_bytes: 0,
          undo_window_bytes: 27 * 1024 ** 2,
        },
      }),
    );
    await page.goto(`${FRONTEND_URL}/app/sync`);
    await expect(page.getByTestId('vault-storage-explanation')).toContainText(
      'current server copy',
    );
    await page.getByRole('button', { name: 'View Vault storage' }).click();
    const storage = page.getByTestId('vault-storage');
    await expect(storage.getByTestId('vault-storage-total')).toHaveText(
      '91 MB of 100 MB used',
    );
    await expect(storage.getByTestId('vault-storage-pack')).toContainText(
      '642 objects',
    );
    await expect(storage.getByTestId('vault-storage-checkpoint')).toContainText(
      '15 objects',
    );
    await expect(page.locator('body')).not.toContainText('[i18n-404:');
    await storage.screenshot({
      path: testInfo.outputPath('vault-storage.png'),
    });
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth))
      .toBeLessThanOrEqual(width);

    await page.goto(`${FRONTEND_URL}/app/storage`);
    await expect(
      page.getByRole('heading', { name: 'Server storage' }),
    ).toBeVisible();
    await expect(page.getByTestId('storage-scope')).toContainText(
      'Cloud Vault backup storage is shown separately',
    );
    await expect(page.getByTestId('storage-loading')).toBeHidden();
    await expect(page.getByTestId('storage-failed')).toBeHidden();
    await expect(page.getByTestId('storage-map')).toBeVisible();
    await expect(page.locator('#boot-splash')).toBeHidden();
    await page.getByRole('main').screenshot({
      path: testInfo.outputPath('server-storage.png'),
    });
    await expect(page.getByTestId('storage-map')).toBeVisible();
  });
}

for (const width of [1200, 390]) {
  test(`account storage compares independent workspace backups at ${width}px`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    const drive = await page.evaluate(() => window.store.getDrive());
    await page.evaluate(
      subject =>
        localStorage.setItem('atomic.vault.optOut', JSON.stringify([subject])),
      drive,
    );
    const enrollments = [
      {
        id: 'small',
        drive_pseudonym: 'small',
        drive_subject: drive,
        agent_subject: 'atomic:agent:one',
        drive_name: 'Personal workspace',
        status: 'active',
        used_bytes: 1024 ** 2,
        quota_bytes: 100 * 1024 ** 2,
        last_backup_at: 1791964800,
      },
      {
        id: 'large',
        drive_pseudonym: 'large',
        drive_subject: 'atomic:older-workspace',
        agent_subject: 'atomic:agent:two',
        drive_name: 'Workspace B',
        status: 'suspended',
        used_bytes: 90 * 1024 ** 2,
        quota_bytes: 100 * 1024 ** 2,
        last_backup_at: 1782864000,
      },
    ];
    await page.route('**/api/me', route =>
      route.fulfill({ json: { email: 'storage@example.com' } }),
    );
    await page.route('**/api/cloud-vault/drives', route =>
      route.fulfill({ json: enrollments }),
    );
    await page.route('**/api/cloud-vault/*/usage', route => {
      const row = enrollments.find(item =>
        route.request().url().includes(`/${item.id}/`),
      )!;

      return route.fulfill({
        json: {
          used_bytes: row.used_bytes,
          quota_bytes: row.quota_bytes,
          by_kind: [{ kind: 'checkpoint', bytes: row.used_bytes, objects: 1 }],
          reclaimable_bytes: 0,
          reclaimable_objects: 0,
          undo_window_bytes: 0,
          undo_window_objects: 0,
          pending_bytes: 0,
          unaccounted_bytes: 0,
        },
      });
    });
    await page.route('**/api/cloud-vault/*/objects', route => {
      const row = enrollments.find(item =>
        route.request().url().includes(`/${item.id}/`),
      )!;

      return route.fulfill({
        json: [
          {
            object_id: row.id,
            object_key: `${row.id}/checkpoint-1.pack`,
            kind: 'checkpoint',
            size_bytes: row.used_bytes,
            key_epoch: 1,
            lane_device_pubkey: null,
            segment: null,
          },
        ],
      });
    });
    const mutations: string[] = [];
    page.on('request', request => {
      if (
        /\/api\/cloud-vault\/.*(?:download|free-up|upload|disable|checkpoint)/.test(
          request.url(),
        ) ||
        (request.url().includes('/api/cloud-vault/') &&
          request.method() !== 'GET')
      )
        mutations.push(request.url());
    });
    await page.goto(`${FRONTEND_URL}/app/storage?view=vault`);
    await expect(page.getByTestId('vault-account-total')).toHaveText(
      '91 MB across 2 workspaces',
    );
    const comparison = page.getByRole('list', {
      name: 'Workspace storage comparison',
    });
    await expect(page.getByTestId('vault-account-tile')).toHaveCount(2);
    await expect(comparison.getByRole('button').first()).toContainText(
      'Workspace B',
    );
    await expect(
      page.getByRole('region', { name: 'Selected workspace storage' }),
    ).toContainText('90 MB of 100 MB for this workspace');
    await page.getByText('Largest backup objects', { exact: true }).click();
    await expect(
      page.getByText('large/checkpoint-1.pack', { exact: true }),
    ).toBeVisible();
    const downloadPromise = page.waitForEvent('download');
    await page
      .getByRole('button', { name: 'Download diagnostic report' })
      .click();
    const download = await downloadPromise;
    const report = JSON.parse(
      await (
        await import('node:fs/promises')
      ).readFile((await download.path())!, 'utf8'),
    );
    expect(report.total_bytes).toBe(91 * 1024 ** 2);
    expect(
      report.workspaces.map(
        (row: { enrollment: { id: string } }) => row.enrollment.id,
      ),
    ).toEqual(['large', 'small']);
    expect(mutations).toEqual([]);
    await expect(page.locator('body')).not.toContainText('[i18n-404:');
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth))
      .toBeLessThanOrEqual(width);
    await page
      .getByRole('main')
      .screenshot({ path: testInfo.outputPath('account-vault-storage.png') });
    await page
      .getByTestId('vault-account-tile')
      .filter({ hasText: 'Personal workspace' })
      .click();
    await expect(
      page.getByRole('region', { name: 'Selected workspace storage' }),
    ).toContainText('1.0 MB of 100 MB for this workspace');
  });
}

for (const width of [1200, 390]) {
  test(`inspects actual encrypted contents and confirms cleanup at ${width}px`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    // Create real resources, file bytes and two encrypted checkpoints. Only
    // the remote ledger/transport is mocked; sizes and contents are measured.
    const backup = await page.evaluate(async () => {
      const store = window.store;
      const drive = store.getDrive();
      if (!drive) throw new Error('Missing test drive');
      localStorage.setItem('atomic.vault.optOut', JSON.stringify([drive]));
      const name = 'https://atomicdata.dev/properties/name';
      const note = await store.newResource({
        parent: drive,
        isA: 'https://atomicdata.dev/classes/DocumentV2',
        propVals: { [name]: 'Project notes' },
      });
      await note.set(
        'https://atomicdata.dev/properties/description',
        'Research notes. '.repeat(1000),
      );
      await note.save();
      const [file] = await store.uploadFiles(
        [
          new File(['Attachment contents. '.repeat(800)], 'Design brief.txt', {
            type: 'text/plain',
          }),
        ],
        drive,
      );
      const wasmUrl = '/wasm/atomic_wasm.js';
      const wasm = await import(/* @vite-ignore */ wasmUrl);
      await wasm.default({ module_or_path: '/wasm/atomic_wasm_bg.wasm' });
      const key = {
        driveKey: wasm.vaultGenerateKey() as Uint8Array,
        keyEpoch: 1,
      };
      const agent = store.getAgent()!;
      const proof =
        agent.vaultProof ?? (await agent.signBytes(wasm.vaultProofMessage()));
      const envelope = wasm.vaultWrapKey(
        key.driveKey,
        Uint8Array.from(atob(proof.replace(/-/g, '+').replace(/_/g, '/')), c =>
          c.charCodeAt(0),
        ),
      ) as string;
      const db = store.getClientDb()!;
      await db.flush();
      const first = (await db.vaultExport(
        drive,
        key,
        'contents',
        'device',
        1,
        1,
        false,
        {},
      ))!;
      await db.vaultCommitSegment('contents', 'device', 1);
      await note.set(name, 'Project notes — revised');
      await note.save();
      await db.flush();
      const second = (await db.vaultExport(
        drive,
        key,
        'contents',
        'device',
        2,
        2,
        false,
        { device: 1 },
      ))!;
      const objects = new Map<
        string,
        { objectKey: string; kind: string; bytes: number[] }
      >();

      for (const snapshot of [first, second]) {
        objects.set(snapshot.objectKey, {
          objectKey: snapshot.objectKey,
          kind: snapshot.kind,
          bytes: [...snapshot.sealed],
        });
        for (const blob of snapshot.blobs)
          objects.set(blob.objectKey, {
            objectKey: blob.objectKey,
            kind: 'blob',
            bytes: [...blob.sealed],
          });
      }

      // A read-only inspection must not bring back this now-deleted document.
      await note.destroy();
      await db.flush();

      return {
        drive,
        envelope,
        file,
        subject: note.subject,
        firstKey: first.objectKey,
        objects: [...objects.values()],
        before: (await db.allSubjects()).filter(subject =>
          subject.startsWith('atomic:'),
        ),
      };
    });
    let objects = backup.objects.map((object, index) => ({
      object_id: String(index),
      object_key: object.objectKey,
      kind: object.kind,
      size_bytes: object.bytes.length,
      key_epoch: 1,
      lane_device_pubkey: null,
      segment: null,
    }));
    const total = () =>
      objects.reduce((sum, object) => sum + object.size_bytes, 0);
    const enrollment = () => ({
      id: 'contents',
      drive_pseudonym: 'contents',
      drive_subject: backup.drive,
      drive_name: 'Storage inspection demo',
      status: 'active',
      used_bytes: total(),
      quota_bytes: 100 * 1024 ** 2,
      last_backup_at: Math.floor(Date.now() / 1000),
    });
    const firstSize = objects.find(
      object => object.object_key === backup.firstKey,
    )!.size_bytes;
    let freed = false;
    const writes: unknown[] = [];
    await page.route('**/api/me', route =>
      route.fulfill({ json: { email: 'inspection@example.com' } }),
    );
    await page.route('**/api/cloud-vault/drives', route =>
      route.fulfill({ json: [enrollment()] }),
    );
    await page.route('**/api/cloud-vault/contents/key', route =>
      route.fulfill({ json: { envelope: backup.envelope, key_epoch: 1 } }),
    );
    await page.route('**/api/cloud-vault/contents/objects', route =>
      route.fulfill({ json: objects }),
    );
    await page.route('**/api/cloud-vault/contents/usage', route =>
      route.fulfill({
        json: {
          used_bytes: total(),
          quota_bytes: 100 * 1024 ** 2,
          by_kind: ['checkpoint', 'blob'].map(kind => ({
            kind,
            bytes: objects
              .filter(o => o.kind === kind)
              .reduce((sum, o) => sum + o.size_bytes, 0),
            objects: objects.filter(o => o.kind === kind).length,
          })),
          reclaimable_bytes: 0,
          reclaimable_objects: 0,
          undo_window_bytes: freed ? 0 : firstSize,
          undo_window_objects: freed ? 0 : 1,
          pending_bytes: 0,
          unaccounted_bytes: 0,
        },
      }),
    );
    const bodyRequests: string[] = [];
    await page.route('**/api/cloud-vault/contents/download-urls', route =>
      route.fulfill({
        json: {
          downloads: objects.map(o => ({
            object_id: o.object_id,
            object_key: o.object_key,
            url: `${FRONTEND_URL}/inspection-object/${o.object_id}`,
          })),
        },
      }),
    );
    await page.route('**/inspection-object/*', route => {
      const object = objects.find(o =>
        route.request().url().endsWith(`/${o.object_id}`),
      )!;
      bodyRequests.push(object.kind);

      return route.fulfill({
        body: Buffer.from(
          backup.objects.find(o => o.objectKey === object.object_key)!.bytes,
        ),
        contentType: 'application/octet-stream',
      });
    });
    await page.route('**/api/cloud-vault/contents/free-up', route => {
      writes.push(route.request().postDataJSON());
      objects = objects.filter(o => o.object_key !== backup.firstKey);
      freed = true;

      return route.fulfill({
        json: {
          pruned: 1,
          blobs_pruned: 0,
          bytes_reclaimed: firstSize,
          delete_failures: 0,
        },
      });
    });
    await page.goto(`${FRONTEND_URL}/app/storage?view=vault`);
    await page
      .getByRole('button', { name: 'Inspect contents', exact: true })
      .click();
    const content = page.getByRole('region', { name: 'Backup contents' });
    await expect(page.getByTestId('vault-contents-map')).toBeVisible({
      timeout: 60_000,
    });
    await expect(content).not.toContainText('could not be inspected');
    const noteTile = page
      .getByTestId('vault-contents-tile')
      .filter({ hasText: 'Project notes' });
    await expect(noteTile).toHaveCount(1);
    await noteTile.click();
    await expect(
      content.getByRole('region', { name: 'Selected backup item' }),
    ).toContainText('2 saved entries');
    await expect(
      page
        .getByTestId('vault-contents-tile')
        .filter({ hasText: 'Design brief.txt (file bytes)' }),
    ).toHaveCount(1);
    expect(bodyRequests).toEqual(['checkpoint', 'checkpoint']);
    expect(
      await page.evaluate(async () =>
        (await window.store.getClientDb()!.allSubjects()).filter(subject =>
          subject.startsWith('atomic:'),
        ),
      ),
    ).toEqual(backup.before);
    expect(writes).toEqual([]);
    await page.setViewportSize({ width, height: 2000 });
    await content.scrollIntoViewIfNeeded();
    await content.screenshot({
      path: testInfo.outputPath('vault-actual-contents.png'),
    });
    await page.setViewportSize({ width, height: 1000 });
    await expect(page.locator('body')).not.toContainText('[i18n-404:');
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth))
      .toBeLessThanOrEqual(width);
    await page
      .getByRole('button', { name: 'Manage backup storage', exact: true })
      .click();
    await page
      .getByTestId('vault-storage')
      .screenshot({ path: testInfo.outputPath('vault-cleanup.png') });
    await page.getByTestId('vault-free-up-undo').click();
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(writes).toEqual([]);
    await page.getByTestId('vault-free-up-undo').click();
    await page
      .getByRole('button', { name: 'Remove retained copies', exact: true })
      .click();
    await expect.poll(() => writes).toEqual([{ include_undo_window: true }]);
    await expect(
      page.getByRole('button', { name: 'Inspect contents', exact: true }),
    ).toBeEnabled();
    const reportDownload = page.waitForEvent('download');
    await page
      .getByRole('button', { name: 'Download diagnostic report' })
      .click();
    const report = JSON.parse(
      await (
        await import('node:fs/promises')
      ).readFile((await (await reportDownload).path())!, 'utf8'),
    );
    expect(report.total_bytes).toBe(total());
    expect(
      report.workspaces[0].objects.some(
        (object: { object_key: string }) =>
          object.object_key === backup.firstKey,
      ),
    ).toBe(false);
    expect(
      await page.evaluate(async () =>
        (await window.store.getClientDb()!.allSubjects()).filter(subject =>
          subject.startsWith('atomic:'),
        ),
      ),
    ).toEqual(backup.before);
  });
}
