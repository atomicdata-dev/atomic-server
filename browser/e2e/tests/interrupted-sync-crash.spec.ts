import { mkdir } from 'node:fs/promises';
import {
  test,
  expect,
  installEmptyDiscoveryRoom,
  type BrowserContext,
  type Page,
} from './fixtures';
import {
  devDrive,
  FRONTEND_URL,
  signIn,
  waitForClientDbReady,
  waitForSynced,
} from './test-utils';
import { DiagnosticCollector } from './diagnostic-collector';

// Deliberately outside smoke: two owned Chromium processes and real OPFS.
// Neither profile belongs to the runner's shared browser or to a real user.
test('two offline clients converge after interrupted sync and SIGKILL', async ({
  playwright,
  launchOptions,
}, testInfo) => {
  test.setTimeout(180_000);
  test.skip(process.platform === 'win32', 'Requires POSIX SIGKILL');
  const nameProperty = 'https://atomicdata.dev/properties/name';
  const descriptionProperty = 'https://atomicdata.dev/properties/description';
  const parentProperty = 'https://atomicdata.dev/properties/parent';
  const ledger = {
    name: 'A acknowledged immediately before crash',
    description: 'B edited during partition',
    rows: ['Offline child A', 'Offline child B'],
  };
  const acknowledgements: Array<{ subject: string; result: string }> = [];
  const diagnostics = new DiagnosticCollector();
  diagnostics.expect(
    'warning',
    /^Service Worker registration blocked by Playwright$/,
    'Service workers are deliberately blocked; registration may retry during the four app navigations',
    8,
  );
  const clients: Array<{
    context: BrowserContext;
    page: Page;
    pid: number;
    online: boolean;
  }> = [];
  let crashed: (typeof clients)[number] | undefined;

  async function launch(profile: string, online = true) {
    const dir = testInfo.outputPath(profile);
    await mkdir(dir, { recursive: true });
    const context = await playwright.chromium.launchPersistentContext(dir, {
      ...launchOptions,
      headless: true,
      serviceWorkers: 'block',
      viewport: { width: 1200, height: 800 },
    });
    diagnostics.start(context);
    await installEmptyDiscoveryRoom(context);
    await context.addInitScript(() =>
      localStorage.setItem('viewTransitionsDisabled', 'true'),
    );
    const browser = context.browser();
    if (!browser) throw new Error('Owned browser missing');
    const cdp = await browser.newBrowserCDPSession();
    const { processInfo } = await cdp.send('SystemInfo.getProcessInfo');
    const pid = processInfo.find(info => info.type === 'browser')?.id;
    await cdp.detach();
    if (!pid) throw new Error('Owned browser PID missing');
    const page = context.pages()[0] ?? (await context.newPage());
    const client = { context, page, pid, online };
    clients.push(client);
    await context.route('**/*', route => {
      const path = new URL(route.request().url()).pathname;

      if (
        !client.online &&
        /^\/(?:did(?::|\/|$)|commit(?:\/|$)|query(?:\/|$)|search(?:\/|$)|download(?:\/|$)|blob(?:\/|$))/.test(
          path,
        )
      ) {
        return route.fulfill({
          status: 503,
          body: 'Partition: data access disabled',
        });
      }

      return route.continue();
    });
    await context.routeWebSocket('**/ws', socket => {
      if (client.online) socket.connectToServer();
      else {
        diagnostics.expect(
          'warning',
          /^\[WS\] close code=1000 reason="partition isolation" wasClean=true opened=false$/,
          'An offline profile cannot recover via WebSocket',
          1,
        );
        socket.close({ code: 1000, reason: 'partition isolation' });
      }
    });

    return client;
  }

  async function localValues(page: Page, subjects: string[]) {
    return page.evaluate(async ids => {
      const db = window.store.getClientDb();
      if (!db?.isReady) throw new Error('Local database unavailable');

      return Promise.all(
        ids.map(async subject => {
          const raw = await db.getResource(subject);

          return raw ? JSON.parse(raw) : null;
        }),
      );
    }, subjects);
  }

  try {
    const a = await launch('client-a');
    const secret = await devDrive(a.page);
    await waitForClientDbReady(a.page);
    const driveUrl = a.page.url();
    const initial = await a.page.evaluate(
      async ({ name, description }) => {
        const resource = await window.store.newResource({
          parent: window.store.getDrive(),
          propVals: {
            [name]: 'Before partition',
            [description]: 'Before partition',
          },
        });
        const result = await resource.save();

        return {
          subject: resource.subject,
          drive: window.store.getDrive(),
          result,
        };
      },
      { name: nameProperty, description: descriptionProperty },
    );
    expect(initial.result).toBe('persisted');
    await waitForSynced(a.page);
    const b = await launch('client-b');
    expect(a.pid).not.toBe(b.pid);
    await b.page.goto(`${FRONTEND_URL}/app/agent`);
    await signIn(b.page, secret);
    await b.page.goto(driveUrl);
    await waitForClientDbReady(b.page);
    expect(
      await b.page.evaluate(
        async ({ subject, name }) =>
          (await window.store.getResource(subject)).get(name),
        { subject: initial.subject, name: nameProperty },
      ),
    ).toBe('Before partition');
    await waitForSynced(b.page);

    for (const client of [a, b]) {
      await client.page.evaluate(() => window.store.disconnect());
      client.online = false;
      expect(
        await client.page.evaluate(() => window.store.serverConnected),
      ).toBe(false);
    }

    const rows: string[] = [];

    for (const [index, client] of [a, b].entries()) {
      const saved = await client.page.evaluate(
        async ({ subject, field, value, rowName, name, drive }) => {
          const doc = await window.store.getResource(subject);
          await doc.set(field, value, false);
          const result = await doc.save();
          const row = await window.store.newResource({
            parent: drive,
            propVals: { [name]: rowName },
          });
          const rowResult = await row.save();

          return [
            { subject: doc.subject, result },
            { subject: row.subject, result: rowResult },
          ];
        },
        {
          subject: initial.subject,
          field: index === 0 ? nameProperty : descriptionProperty,
          value: index === 0 ? 'A first offline edit' : ledger.description,
          rowName: ledger.rows[index],
          name: nameProperty,
          drive: initial.drive,
        },
      );
      for (const ack of saved) expect(ack.result).toBe('offline');
      acknowledgements.push(...saved);
      rows.push(saved[1].subject);
    }

    a.online = true;
    // Intercept the real outgoing SYNC probe (0x30), forward it, then close
    // synchronously before a response can be delivered. No timing sleeps.
    await a.page.evaluate(
      () =>
        new Promise<void>((resolve, reject) => {
          const original = WebSocket.prototype.send;
          const timer = setTimeout(() => {
            WebSocket.prototype.send = original;
            reject(new Error('SYNC probe was never sent'));
          }, 15_000);

          WebSocket.prototype.send = function (data) {
            original.call(this, data);

            if (data instanceof Uint8Array && data[0] === 0x30) {
              WebSocket.prototype.send = original;
              clearTimeout(timer);
              window.store.disconnect();
              resolve();
            }
          };

          window.store.reconnect().catch(error => {
            clearTimeout(timer);
            WebSocket.prototype.send = original;
            reject(error);
          });
        }),
    );
    a.online = false;
    const finalAck = await a.page.evaluate(
      async ({ subject, name, value }) => {
        const doc = await window.store.getResource(subject);
        await doc.set(name, value, false);
        const result = await doc.save();

        return {
          subject: doc.subject,
          result,
          version: [...doc.getLoroDoc()!.oplogVersion().toJSON()].sort(),
        };
      },
      { subject: initial.subject, name: nameProperty, value: ledger.name },
    );
    expect(finalAck.result).toBe('offline');
    acknowledgements.push(finalAck);
    // No flush, navigation or graceful close between save acknowledgement and kill.
    const browser = a.context.browser()!;
    const disconnected = new Promise<void>(resolve =>
      browser.once('disconnected', () => resolve()),
    );
    process.kill(a.pid, 'SIGKILL');
    await disconnected;
    crashed = a;
    await testInfo.attach('acknowledgement-ledger', {
      body: JSON.stringify({
        ledger,
        acknowledgements,
        subject: initial.subject,
        rows,
      }),
      contentType: 'application/json',
    });

    const restarted = await launch('client-a', false);
    await restarted.page.goto(driveUrl);
    await waitForClientDbReady(restarted.page);
    const recoveredSnapshot = await restarted.page.evaluate(
      async ({ subject, name }) => {
        const { snapshot } = await window.store
          .getClientDb()!
          .getResourceWithSnapshot(subject);
        // The drive may not be loaded yet after the restart; getResourceLoading
        // always hands back a Resource instance to take the class from.
        const example = window.store.getResourceLoading(
          window.store.getDrive()!,
        );
        const ResourceType = example.constructor as new (
          id: string,
        ) => typeof example;
        const resource = new ResourceType(subject);
        const imported = resource.importLoroUpdate(snapshot!, true);

        return {
          complete: imported.complete,
          name: resource.get(name),
          version: [...resource.getLoroDoc()!.oplogVersion().toJSON()].sort(),
        };
      },
      { subject: initial.subject, name: nameProperty },
    );
    await testInfo.attach('recovered-snapshot', {
      body: JSON.stringify(recoveredSnapshot),
      contentType: 'application/json',
    });
    expect(recoveredSnapshot).toEqual({
      complete: true,
      name: ledger.name,
      version: finalAck.version,
    });
    // Read OPFS directly while both HTTP and WS recovery are prohibited.
    const recovered = await localValues(restarted.page, [
      initial.subject,
      rows[0],
    ]);
    expect(recovered[0]?.[nameProperty]).toBe(ledger.name);
    expect(recovered[1]?.[nameProperty]).toBe(ledger.rows[0]);
    expect(
      await restarted.page.evaluate(() => window.store.serverConnected),
    ).toBe(false);
    // localStorage queue persistence is not the recovery oracle: the durable
    // Loro snapshot can also be reconciled by version vector after a crash.
    await testInfo.attach('recovered-outbox', {
      body: JSON.stringify(
        await restarted.page.evaluate(() =>
          window.store.outbox
            .pending()
            .map(entry => ({ subject: entry.subject })),
        ),
      ),
      contentType: 'application/json',
    });

    async function reconnectAndWait(page: Page) {
      const previous = await page.evaluate(
        () => window.store.getSyncStatus().lastDriveSync?.timestamp,
      );
      await page.evaluate(() => window.store.reconnect());
      await expect
        .poll(
          () =>
            page.evaluate(before => {
              const status = window.store.getSyncStatus();

              return (
                !!status.lastDriveSync &&
                status.lastDriveSync.timestamp !== before &&
                !status.syncInProgress &&
                status.pendingDirtyCount === 0
              );
            }, previous),
          { timeout: 30_000 },
        )
        .toBe(true);
    }

    b.online = true;
    await reconnectAndWait(b.page);
    restarted.online = true;
    await reconnectAndWait(restarted.page);
    // One independent read after completion: polling here would hide an early
    // sync-complete signal. The server must already have acknowledged this edit.
    const serverName = await restarted.page.evaluate(
      async ({ subject, name }) => {
        const StoreType = window.store.constructor as new (options: {
          serverUrl: string;
          connect: boolean;
        }) => typeof window.store;
        const reader = new StoreType({
          serverUrl: window.store.getServerUrl(),
          connect: false,
        });
        reader.setAgent(window.store.getAgent());
        const resource = await reader.fetchResourceFromServer(subject, {
          noWebSocket: true,
        });

        return resource?.get(name);
      },
      { subject: initial.subject, name: nameProperty },
    );
    expect(serverName).toBe(ledger.name);
    await reconnectAndWait(b.page);

    for (const client of [restarted, b]) {
      await expect
        .poll(
          async () => {
            const values = await localValues(client.page, [
              initial.subject,
              ...rows,
            ]);

            return [
              values[0]?.[nameProperty],
              values[0]?.[descriptionProperty],
              ...values
                .slice(1)
                .map(value => [value?.[nameProperty], value?.[parentProperty]]),
            ];
          },
          {
            timeout: 30_000,
            message: `${client === restarted ? 'Restarted A' : 'Client B'} must match the acknowledgement ledger`,
          },
        )
        .toEqual([
          ledger.name,
          ledger.description,
          ...ledger.rows.map(value => [value, initial.drive]),
        ]);
      const status = await client.page.evaluate(() =>
        window.store.getSyncStatus(),
      );
      expect(status.pendingDirtyCount).toBe(0);
      expect(status.blockedCount).toBe(0);
    }

    // Force HTTP after proving the local replicas agree, to check server state.
    const remote = await b.page.evaluate(
      async ({ subjects, name, description, parent }) => {
        const StoreType = window.store.constructor as new (options: {
          serverUrl: string;
          connect: boolean;
        }) => typeof window.store;
        const reader = new StoreType({
          serverUrl: window.store.getServerUrl(),
          connect: false,
        });
        reader.setAgent(window.store.getAgent());
        const values = [];

        for (const subject of subjects) {
          const resource = await reader.fetchResourceFromServer(subject, {
            noWebSocket: true,
          });
          values.push([
            resource?.get(name),
            resource?.get(description),
            resource?.get(parent),
          ]);
        }

        return values;
      },
      {
        subjects: [initial.subject, ...rows],
        name: nameProperty,
        description: descriptionProperty,
        parent: parentProperty,
      },
    );
    expect(remote[0]).toEqual([ledger.name, ledger.description, initial.drive]);
    expect(remote.slice(1).map(value => [value[0], value[2]])).toEqual(
      ledger.rows.map(value => [value, initial.drive]),
    );
  } finally {
    diagnostics.dispose();
    await testInfo.attach('browser-diagnostics', {
      body: JSON.stringify(diagnostics.snapshot()),
      contentType: 'application/json',
    });

    for (const client of clients) {
      if (client === crashed) continue;

      if (!client.page.isClosed()) {
        const evidence = await client.page
          .evaluate(() => ({
            status: window.store?.getSyncStatus(),
            diagnostics: window.store?.diagnostics.capture(),
          }))
          .catch(() => undefined);
        if (evidence)
          await testInfo.attach(`client-${client.pid}-diagnostics`, {
            body: JSON.stringify(evidence),
            contentType: 'application/json',
          });
      }

      await client.context.close();
    }
  }

  expect(diagnostics.snapshot().unexpected).toEqual([]);
});
