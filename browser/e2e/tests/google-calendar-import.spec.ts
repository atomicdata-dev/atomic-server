import { test, expect } from '@playwright/test';
import { before } from './test-utils';

// Provider responses are synthetic; schema installation, sandbox review/apply
// and Calendar rendering use the real app and AtomicServer.
test('Google import installs a Calendar view with all-day and timed events', async ({
  page,
}) => {
  test.setTimeout(120_000);
  await before({ page });
  const today = new Date().toISOString().slice(0, 10);
  const fields = ['start', 'end', 'attendees'];
  const fetched = {
    platform: 'google-calendar',
    ontology: {
      description: 'Synthetic Calendar',
      terms: [
        {
          path: 'event',
          kind: 'class',
          shortname: 'event',
          description: 'Events',
          requires: [],
          recommends: fields,
        },
        ...fields.map(shortname => ({
          path: shortname,
          kind: 'property',
          shortname,
          description: shortname,
          datatype: 'https://atomicdata.dev/datatypes/json',
          requires: [],
          recommends: [],
        })),
      ],
    },
    records: [
      {
        resource: 'event',
        namespace: 'synthetic',
        id: 'all-day',
        name: 'Calendar all-day fixture',
        values: { start: { date: today }, end: { date: today } },
      },
      {
        resource: 'event',
        namespace: 'synthetic',
        id: 'timed',
        name: 'Calendar timed fixture',
        values: {
          start: { dateTime: `${today}T00:30:00+02:00` },
          attendees: [{ email: 'synthetic@example.com' }],
        },
      },
    ],
  };
  await page.route('**/integration-proxy/catalog', route =>
    route.fulfill({ json: { platforms: ['google-calendar'] } }),
  );
  await page.route('**/integration-proxy/platform?*', route =>
    route.fulfill({ json: { parameters: [], collections: ['events'] } }),
  );
  await page.route('**/integration-proxy/fetch', route =>
    route.fulfill({ json: fetched }),
  );
  await page.evaluate(() => {
    const store = window.store!;
    const drive = store.getDrive()!;
    const actor = store.getAgent()!.subject;
    localStorage.setItem(
      `localthought:${JSON.stringify([drive, actor, 'google-calendar'])}`,
      JSON.stringify({
        drive,
        actor,
        platform: 'google-calendar',
        connection: 'synthetic-calendar',
      }),
    );
  });
  await page.getByRole('link', { name: 'Integrations', exact: true }).click();
  await page
    .locator('[data-integration="google-calendar"]')
    .getByRole('button', { name: 'Set up connection' })
    .click();
  await page.getByRole('button', { name: 'Fetch and preview' }).click();
  await expect(
    page.getByRole('button', { name: 'Apply 2 changes', exact: true }),
  ).toBeEnabled({ timeout: 60_000 });
  await page
    .getByRole('button', { name: 'Apply 2 changes', exact: true })
    .click();
  await page
    .getByRole('link', { name: 'Open imported records', exact: true })
    .click();
  await expect(page.getByTestId('calendar-view')).toBeVisible({
    timeout: 30_000,
  });
  const day = page.locator(
    `[data-testid="calendar-day"][data-date="${today}"]`,
  );
  await expect(day.getByTestId('calendar-event')).toHaveCount(2);
  await day.getByText('Calendar timed fixture', { exact: true }).click();
  await expect(page.getByRole('dialog').last()).toContainText(
    'Attendees and RSVP',
  );
});
