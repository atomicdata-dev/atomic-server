import { test, expect } from '@playwright/test';
import { mockProxy } from '../../../integrations/localthought/mock-proxy.mjs';
const FRONTEND_URL = process.env.FRONTEND_URL ?? 'http://localhost:6747';
const SERVER_URL = process.env.SERVER_URL ?? 'http://localhost:9883';
test.use({ serviceWorkers: 'block' });

// Reuse the browser transport and HTTP mock from the Devonian integration.
// No real provider credentials are used.
for (const keepSeries of [false, true]) {
  test(`Calendar ${keepSeries ? 'series' : 'instances'} installs in background, refreshes on opening and persists without AtomicServer`, async ({
    page,
  }) => {
    test.setTimeout(180_000);
    await page.clock.install();
    const proxy = mockProxy({ frontendOrigin: new URL(FRONTEND_URL).origin });
    const month = new Date().toISOString().slice(0, 7);
    proxy.calendar.events[0].start = { date: `${month}-10` };
    proxy.calendar.events[0].end = { date: `${month}-13` };

    if (keepSeries) {
      const event = proxy.calendar.events[1];
      event.start = { dateTime: `${month}-05T09:00:00Z`, timeZone: 'UTC' };
      event.end = { dateTime: `${month}-05T10:00:00Z` };
      event.recurrence = ['RRULE:FREQ=WEEKLY;COUNT=3'];
      delete event.recurringEventId;
      delete event.originalStartTime;
      proxy.calendar.events.push(
        {
          ...event,
          id: 'moved',
          summary: 'Moved meeting',
          recurrence: undefined,
          recurringEventId: event.id,
          originalStartTime: { dateTime: `${month}-12T09:00:00Z` },
          start: { dateTime: `${month}-14T11:00:00Z` },
          end: { dateTime: `${month}-14T12:00:00Z` },
        },
        {
          ...event,
          id: 'cancelled',
          summary: 'Cancelled meeting',
          status: 'cancelled',
          recurrence: undefined,
          recurringEventId: event.id,
          originalStartTime: { dateTime: `${month}-19T09:00:00Z` },
        },
      );
    }

    const chipCount = keepSeries ? 5 : 4;
    await new Promise<void>(resolve => proxy.listen(0, '127.0.0.1', resolve));
    const port = (proxy.address() as { port: number }).port;
    const proxyOrigin = `http://127.0.0.1:${port}`;
    const configuredProxy =
      process.env.VITE_INTEGRATION_PROXY_URL || 'https://localthought.io';
    await page.routeWebSocket('**/*', socket => socket.close());
    const forbidden: string[] = [];
    const providerMethods: string[] = [];
    let releaseImport!: () => void;
    const importGate = new Promise<void>(resolve => {
      releaseImport = resolve;
    });
    let failRefresh = false;
    // Forward the configured proxy to this test's isolated HTTP fixture. Consent,
    // PKCE redemption, code rotation, pagination and WASM code remain real.
    await page.route('**/*', async route => {
      const request = route.request();
      const url = new URL(request.url());

      if (/^\/(integration-proxy|plugin-run|commit)(\/|$)/.test(url.pathname)) {
        forbidden.push(url.pathname);

        return route.abort();
      }

      if (url.origin === configuredProxy) {
        if (url.pathname.startsWith('/proxy/')) {
          providerMethods.push(request.method());
          if (providerMethods.length > 1) await importGate;
        }

        const response = await route.fetch({
          url: `${proxyOrigin}${url.pathname}${url.search}`,
          maxRedirects: 0,
        });

        if (failRefresh && url.pathname.startsWith('/proxy/'))
          return route.fulfill({
            response,
            status: 503,
            body: '{"error":"temporarily unavailable"}',
          });

        return route.fulfill({ response });
      }

      if (
        url.origin === new URL(SERVER_URL).origin &&
        url.origin !== new URL(FRONTEND_URL).origin
      )
        return route.abort();

      return route.continue();
    });

    try {
      await page.goto(`${FRONTEND_URL}/app/dev-drive`);
      await page.waitForURL(/app\/show\?subject=/, { timeout: 60000 });

      const setup = async () => {
        await page
          .getByRole('link', { name: 'Integrations', exact: true })
          .click();
        await page
          .locator('[data-integration="proxy:google-calendar"]')
          .getByRole('button', { name: 'Set up connection' })
          .click();
      };

      await setup();
      await page
        .getByRole('button', { name: 'Install and connect', exact: true })
        .click();
      await page
        .getByRole('button', {
          name: 'Use LocalThought to sync Google Calendar with your Atomic Data Hub',
          exact: true,
        })
        .click();
      await expect(
        page.getByRole('button', {
          name: 'Complete installation',
          exact: true,
        }),
      ).toBeVisible();
      expect(page.url()).not.toContain('connection_code');

      await page
        .getByLabel('Keep recurring series (fetch full calendars)')
        .setChecked(keepSeries);
      await page
        .getByRole('button', { name: 'Complete installation', exact: true })
        .click();
      // Validation uses one API request; the real import is held until after
      // installation has completed and the empty folder is already usable.
      await expect(
        page.getByText(
          'Installed. Your records are syncing in the background.',
        ),
      ).toBeVisible();
      await expect(
        page.getByRole('button', { name: /^Apply .* changes?$/ }),
      ).toHaveCount(0);
      await page
        .getByRole('link', { name: 'Open folder', exact: true })
        .click();
      await expect(
        page.getByRole('status').filter({ hasText: 'Syncing…' }),
      ).toBeVisible();
      const folderUrl = page.url();
      await expect.poll(() => providerMethods.length).toBe(2);
      releaseImport();
      await expect(
        page.getByRole('status').filter({ hasText: 'Last synced' }),
      ).toBeVisible({ timeout: 60000 });

      const openTable = async () => {
        await page
          .locator('[data-test="folder-list"]')
          .getByRole('link', { name: 'Google Calendar', exact: true })
          .click();
        await expect(page.getByTestId('calendar-view')).toBeVisible();
        await expect(
          page.getByRole('status').filter({ hasText: 'Last synced' }),
        ).toBeVisible({ timeout: 60000 });
      };

      await openTable();

      for (const day of ['10', '11', '12']) {
        await expect(
          page.locator(`[data-date="${month}-${day}"] [data-all-day="true"]`),
        ).toHaveText('All dayCalendar all-day fixture');
      }

      await expect(
        page.locator(`[data-date="${month}-13"] [data-all-day="true"]`),
      ).toHaveCount(0);
      await expect(page.getByTestId('calendar-event')).toHaveCount(chipCount);

      if (keepSeries) {
        await expect(
          page.locator(`[data-date="${month}-14"] [data-recurring="true"]`),
        ).toHaveText(/Moved meeting/);
        await expect(
          page.locator(`[data-date="${month}-12"] [data-recurring="true"]`),
        ).toHaveCount(0);
        await expect(
          page.getByText('Cancelled meeting', { exact: true }),
        ).toHaveCount(0);
      }

      await page
        .getByTestId('calendar-event')
        .filter({ hasText: 'Calendar timed fixture' })
        .click();
      await expect(page.getByRole('dialog').last()).toContainText(
        'Recurring event',
      );
      await expect(page.getByRole('dialog').last()).toContainText(
        'Attendees and RSVP',
      );
      await page.keyboard.press('Escape');
      const original = await page.evaluate(async () => {
        const store = window.store!;
        const table = new URL(location.href).searchParams.get('subject')!;
        const result = await store.queryLocalDb({
          drive: store.getDrive()!,
          property: 'https://atomicdata.dev/properties/parent',
          value: table,
          limit: 100,
        });
        const subjects = result!.subjects.sort();
        const rows = await Promise.all(
          subjects.map(subject => store.getResource(subject)),
        );
        const row = rows.find(
          item =>
            item.get('https://atomicdata.dev/properties/name') ===
            'Calendar all-day fixture',
        )!;
        await row.set(
          'https://atomicdata.dev/properties/name',
          'My local event title',
        );
        await row.set(
          'https://atomicdata.dev/properties/description',
          'Atomic-only notes',
        );
        await row.save();
        await store.getClientDb()!.flush();

        return { subjects, table, annotated: row.subject };
      });
      proxy.calendar.events[1].summary = 'Calendar refreshed fixture';
      // A fresh page restores browser-owned settings. Opening the folder is
      // enough to import remote changes: no visit to setup or Sync now.
      await page.goto(folderUrl);
      await expect(
        page.getByRole('status').filter({ hasText: 'Last synced' }),
      ).toBeVisible({ timeout: 60000 });
      await openTable();
      await expect(
        page
          .getByTestId('calendar-event')
          .filter({ hasText: 'Calendar refreshed fixture' }),
      ).toBeVisible();
      await expect(page.getByTestId('calendar-event')).toHaveCount(chipCount);
      const restored = await page.evaluate(async saved => {
        const store = window.store!;
        const result = await store.queryLocalDb({
          drive: store.getDrive()!,
          property: 'https://atomicdata.dev/properties/parent',
          value: saved.table,
          limit: 100,
        });

        return {
          subjects: result!.subjects.sort(),
          name: (await store.getResource(saved.annotated)).get(
            'https://atomicdata.dev/properties/name',
          ),
          note: (await store.getResource(saved.annotated)).get(
            'https://atomicdata.dev/properties/description',
          ),
        };
      }, original);
      expect(restored.subjects).toEqual(original.subjects);
      expect(restored.note).toBe('Atomic-only notes');
      expect(restored.name).toBe('My local event title');
      proxy.calendar.events[1].summary = 'Calendar scheduled fixture';
      await page.clock.fastForward(5 * 60 * 1000);
      await expect(
        page
          .getByTestId('calendar-event')
          .filter({ hasText: 'Calendar scheduled fixture' }),
      ).toBeVisible({ timeout: 60000 });
      await expect(
        page.getByRole('status').filter({ hasText: 'Last synced' }),
      ).toBeVisible();
      expect(providerMethods.length).toBeGreaterThan(4);
      expect(providerMethods.every(method => method === 'GET')).toBe(true);
      expect(
        proxy.calendar.requests.filter(r => r.query.pageToken === 'second'),
      ).not.toHaveLength(0);
      // A failed refresh leaves the last imported records readable; reopening
      // retries and recovers without a manual action.
      failRefresh = true;
      await page.reload();
      await expect(
        page.getByRole('status').filter({ hasText: 'Sync needs attention' }),
      ).toBeVisible({ timeout: 60000 });
      await expect(page.getByTestId('calendar-event')).toHaveCount(chipCount);
      failRefresh = false;
      await page.reload();
      await expect(
        page.getByRole('status').filter({ hasText: 'Last synced' }),
      ).toBeVisible({ timeout: 60000 });
      await expect(page.getByTestId('calendar-event')).toHaveCount(chipCount);
      expect(forbidden).toEqual([]);
    } finally {
      releaseImport();
      await new Promise<void>((resolve, reject) =>
        proxy.close(error => (error ? reject(error) : resolve())),
      );
    }
  });
}
