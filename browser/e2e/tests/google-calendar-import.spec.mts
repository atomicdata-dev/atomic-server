import { test, expect } from '@playwright/test';
import {
  mockProxy,
  tenantSecret,
} from '../../../integrations/localthought/mock-proxy.mjs';
const FRONTEND_URL = process.env.FRONTEND_URL ?? 'http://localhost:6747';
const SERVER_URL = process.env.SERVER_URL ?? 'http://localhost:9883';
test.use({ serviceWorkers: 'block' });

// Reuse the browser transport and HTTP mock from the Devonian integration.
// The tenant secret is a public fixture. No real provider credentials are used.
for (const keepSeries of [false, true]) {
  test(`Calendar ${keepSeries ? 'series' : 'instances'} import, refresh and persist without AtomicServer`, async ({
    page,
  }) => {
    test.setTimeout(180_000);
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
    // Forward the configured proxy to this test's isolated HTTP fixture. All
    // tenant proof, consent, code rotation, pagination and WASM code remain real.
    await page.route('**/*', async route => {
      const request = route.request();
      const url = new URL(request.url());

      if (/^\/(integration-proxy|plugin-run|commit)(\/|$)/.test(url.pathname)) {
        forbidden.push(url.pathname);

        return route.abort();
      }

      if (url.origin === configuredProxy) {
        if (url.pathname.startsWith('/proxy/'))
          providerMethods.push(request.method());
        const response = await route.fetch({
          url: `${proxyOrigin}${url.pathname}${url.search}`,
          maxRedirects: 0,
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
          .locator('[data-integration="google-calendar"]')
          .getByRole('button', { name: 'Set up connection' })
          .click();
      };

      await setup();
      await page.getByLabel('LocalThought tenant secret').fill(tenantSecret);
      await page
        .getByRole('button', { name: 'Install and connect', exact: true })
        .click();
      await page
        .getByRole('button', { name: 'Connect test account', exact: true })
        .click();
      await expect(
        page.getByRole('button', { name: 'Fetch and preview', exact: true }),
      ).toBeVisible();
      expect(page.url()).not.toContain('connection_code');
      expect(
        await page.evaluate(() =>
          JSON.stringify({ ...localStorage, ...sessionStorage }),
        ),
      ).not.toContain(tenantSecret);

      const apply = async (count: number) => {
        await page
          .getByLabel('Keep recurring series (fetch full calendars)')
          .setChecked(keepSeries);
        await page
          .getByRole('button', { name: 'Fetch and preview', exact: true })
          .click();
        await page
          .getByRole('button', {
            name: new RegExp(`^Apply ${count} changes?$`),
          })
          .click();
        await page
          .getByRole('link', { name: 'Open imported records', exact: true })
          .click();
        await expect(page.getByTestId('calendar-view')).toBeVisible();
      };

      await apply(keepSeries ? 4 : 2);

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
        const row = await store.getResource(subjects[0]);
        await row.set(
          'https://atomicdata.dev/properties/description',
          'Atomic-only notes',
        );
        await row.save();
        await store.getClientDb()!.flush();

        return { subjects, table, annotated: row.subject };
      });
      await page.reload();
      await expect(page.getByTestId('calendar-event')).toHaveCount(chipCount);
      proxy.calendar.events[1].summary = 'Calendar refreshed fixture';
      await setup();
      await apply(1);
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
          note: (await store.getResource(saved.annotated)).get(
            'https://atomicdata.dev/properties/description',
          ),
        };
      }, original);
      expect(restored.subjects).toEqual(original.subjects);
      expect(restored.note).toBe('Atomic-only notes');
      expect(providerMethods).toEqual(['GET', 'GET', 'GET', 'GET']);
      expect(
        proxy.calendar.requests.filter(r => r.query.pageToken === 'second'),
      ).toHaveLength(2);
      expect(forbidden).toEqual([]);
    } finally {
      await new Promise<void>((resolve, reject) =>
        proxy.close(error => (error ? reject(error) : resolve())),
      );
    }
  });
}
