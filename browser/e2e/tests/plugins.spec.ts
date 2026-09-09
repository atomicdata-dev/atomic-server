import { test, expect } from '@playwright/test';
import {
  before,
  createTableFromDialog,
  getDevDriveSecret,
  SERVER_URL,
} from './test-utils';
import {
  Agent,
  getPluginSync,
  pluginSyncSchedule,
  dataBrowser,
} from '@tomic/lib';

/**
 * The whole manual-run path, which is otherwise only ever verified by hand:
 * create a plugin, run it, review what it proposes, apply, and find the run in
 * the log. Everything below the UI has unit tests; this is the part that only
 * a browser can answer.
 */
test.describe('plugins', () => {
  test.beforeEach(before);

  test('Pets imports from the mock integration proxy after account connection and review', async ({
    page,
  }) => {
    test.skip(
      !process.env.ATOMIC_MOCK_INTEGRATION_PROXY,
      'Run with the documented mock integration-proxy server configuration',
    );

    // CI's browser and server are in different containers. Forward the mock's
    // loopback address to the server container before catalog loading starts.
    if (process.env.ATOMIC_SERVICE_URL)
      await page.route('http://127.0.0.1:19090/**', async route => {
        const target = new URL(route.request().url());
        target.hostname = new URL(process.env.ATOMIC_SERVICE_URL!).hostname;
        const response = await route.fetch({
          url: target.href,
          maxRedirects: 0,
        });
        await route.fulfill({ response });
      });
    await page.getByRole('link', { name: 'Integrations', exact: true }).click();
    const pets = page.locator('[data-integration=pets]');
    await expect(
      pets.getByRole('heading', { name: 'Pets', exact: true }),
    ).toBeVisible();
    await pets.getByRole('button', { name: 'Set up connection' }).click();

    const setup = page.locator('dialog[open]');
    await expect(
      setup.getByRole('button', { name: 'Install and connect', exact: true }),
    ).toBeVisible();
    await setup
      .getByLabel('LocalThought tenant secret')
      .fill('bW9jay10ZW5hbnQ.mock-signature');
    await setup
      .getByRole('button', { name: 'Install and connect', exact: true })
      .click();

    await expect(
      page.getByRole('heading', { name: 'Mock integration proxy' }),
    ).toBeVisible();
    await page.getByRole('button', { name: 'Connect test account' }).click();
    await expect(page).not.toHaveURL(/connection_code=/);
    await page.getByRole('button', { name: 'Fetch and preview' }).click();

    const review = page.locator('dialog[open]');
    // The browser creates the local ontology, tables and reviewed proposal.
    // Allow the one-time installation more than the interaction timeout.
    await expect(
      review.getByRole('button', { name: 'Apply 5 changes', exact: true }),
    ).toBeEnabled({ timeout: 45_000 });
    await review
      .getByRole('button', { name: 'Apply 5 changes', exact: true })
      .click();

    await page
      .getByRole('link', { name: 'Open imported records', exact: true })
      .click();
    const main = page.getByRole('main');
    await expect(
      main.getByRole('heading', { name: 'Pets', exact: true }),
    ).toBeVisible();
    for (const name of ['Rex', 'Whiskers', 'Tweety', 'Nibbles', 'Bubbles'])
      await expect(main.getByText(name, { exact: true }).first()).toBeVisible();
    // Numeric and boolean properties must retain their Atomic datatype, not become JSON blobs.
    const datatypes = await page.evaluate(async () => {
      const store = window.store!;
      const table = await store.getResource(
        new URL(location.href).searchParams.get('subject')!,
      );
      const klass = await store.getResource(
        table.get('https://atomicdata.dev/properties/classtype') as string,
      );
      const fields = klass.get(
        'https://atomicdata.dev/properties/recommends',
      ) as string[];
      const properties = await Promise.all(
        fields.map(s => store.getResource(s)),
      );

      return Object.fromEntries(
        properties.map(p => [
          p.get('https://atomicdata.dev/properties/name'),
          p.get('https://atomicdata.dev/properties/datatype'),
        ]),
      );
    });
    expect(datatypes).toMatchObject({
      age: 'https://atomicdata.dev/datatypes/integer',
      vaccinated: 'https://atomicdata.dev/datatypes/boolean',
      weight: 'https://atomicdata.dev/datatypes/float',
      'updated at': 'https://atomicdata.dev/datatypes/timestamp',
    });
  });

  test('a published release is discoverable and creates an independent draft', async ({
    page,
  }) => {
    await newPlugin(page);
    const source = `export const manifest = { schemaVersion: 1 };
export function run() { return { intents: [] }; }
// release fixture ${Date.now()}`;
    await setSource(page, source);
    const original = page.url();
    await page.getByRole('tab', { name: 'Code', exact: true }).click();
    const publication = page.waitForResponse(
      response =>
        response.url().endsWith('/plugin-release') &&
        response.request().method() === 'POST',
    );
    await page
      .getByRole('button', { name: 'Publish to integration store' })
      .click();
    const published = await publication;
    expect(published.ok()).toBe(true);
    const { id } = await published.json();
    await expect(
      page.getByRole('heading', { name: 'Integrations', exact: true }),
    ).toBeVisible();
    const card = page
      .locator('[data-release]')
      .filter({
        has: page.getByRole('heading', { name: 'New plugin', exact: true }),
      })
      .filter({ hasText: id });
    await expect(card.getByText('Unverified', { exact: true })).toBeVisible();
    await page.screenshot({
      path: '/tmp/atomic-integration-store.png',
      fullPage: true,
    });
    await card.getByRole('button', { name: 'Create draft' }).click();
    await expect(
      page
        .getByRole('main')
        .getByRole('heading', { name: 'New plugin', level: 1 }),
    ).toBeVisible();
    expect(page.url()).not.toBe(original);
    await page.goto(original);
    await page.getByRole('tab', { name: 'Code', exact: true }).click();
    await expect(
      page
        .getByRole('main')
        .getByText('export const manifest', { exact: false }),
    ).toBeVisible();
  });

  for (const managed of [false, true]) {
    test(`Notion ${managed ? 'managed' : 'direct'} OAuth selects a database by name and reports revoked access`, async ({
      page,
    }) => {
      const connection = {
        id: 'fixture-connection',
        name: 'Design team',
        workspace: 'fixture-workspace',
      };
      await page.route('**/integration-oauth/notion/list', route =>
        route.fulfill({ json: { configured: true, connections: [] } }),
      );
      await page.route('**/integration-oauth/notion/start', route =>
        route.fulfill({
          json: {
            state: 'fixture-state',
            ...(managed ? { mode: 'managed' } : {}),
            url: 'http://localhost:9898/integration-oauth/notion/callback?state=fixture-state&code=fixture',
          },
        }),
      );
      await page
        .context()
        .route('**/integration-oauth/notion/callback?**', route =>
          route.fulfill({
            contentType: 'text/html',
            body: managed
              ? 'Authorization finished. Return to Atomic.'
              : `<script>opener.postMessage({type:'atomic-notion-oauth',state:'fixture-state',code:'fixture',error:null},'http://localhost:6747')</script>`,
          }),
        );
      let finishCalls = 0;
      await page.route('**/integration-oauth/notion/finish', async route => {
        expect(route.request().postDataJSON()).toMatchObject({
          state: 'fixture-state',
          ...(managed ? {} : { code: 'fixture' }),
        });
        if (managed)
          expect(route.request().postDataJSON()).not.toHaveProperty('code');
        finishCalls++;
        await route.fulfill({
          json: managed && finishCalls === 1 ? { pending: true } : connection,
        });
      });
      let credentialBindings = 0;
      await page.route('**/integration-oauth/notion/bind', async route => {
        expect(route.request().postDataJSON()).toMatchObject({
          connection: connection.id,
        });
        expect(route.request().postDataJSON()).not.toHaveProperty('value');
        credentialBindings++;
        await route.fulfill({ json: true });
      });
      await page.route('**/plugin-external-read', async route => {
        const operation = route.request().postDataJSON().intent.operation;
        const data =
          operation === 'schema'
            ? {
                id: '11111111-1111-4111-8111-111111111111',
                properties: {
                  Name: { id: 'title', name: 'Name', type: 'title' },
                },
              }
            : { results: [], has_more: false, next_cursor: null };
        await route.fulfill({
          json: { status: 200, body: JSON.stringify(data) },
        });
      });
      let revoked = false;
      await page.route('**/integration-oauth/notion/discover', async route => {
        expect(route.request().postDataJSON().connection).toBe(connection.id);
        if (revoked)
          await route.fulfill({
            status: 401,
            body: 'Notion access was revoked. Reconnect Notion to continue.',
          });
        else
          await route.fulfill({
            json: {
              results: [
                {
                  id: '11111111-1111-4111-8111-111111111111',
                  name: 'Project tasks',
                  icon: '✅',
                },
              ],
              cursor: null,
            },
          });
      });
      await page
        .getByRole('link', { name: 'Integrations', exact: true })
        .click();
      await page
        .locator('[data-integration=notion]')
        .getByRole('button', { name: 'Set up connection' })
        .click();
      await page
        .getByRole('button', { name: 'Connect Notion', exact: true })
        .click();
      await expect(
        page.getByLabel('Notion workspace', { exact: true }),
      ).toHaveValue(connection.id);
      await page.getByLabel('Find a database', { exact: true }).fill('Project');
      await page
        .getByRole('button', { name: 'Find databases', exact: true })
        .click();
      await page
        .getByLabel('Database', { exact: true })
        .selectOption({ label: '✅ Project tasks' });
      await expect(
        page.getByRole('button', {
          name: 'Continue to sync setup',
          exact: true,
        }),
      ).toBeEnabled();
      await expect(
        page.getByLabel('Data source ID', { exact: true }),
      ).not.toBeVisible();
      revoked = true;
      await page
        .getByRole('button', { name: 'Find databases', exact: true })
        .click();
      await expect(page.getByRole('alert')).toContainText('Reconnect Notion');
      await expect(
        page.getByRole('button', { name: 'Reconnect Notion', exact: true }),
      ).toBeEnabled();
      revoked = false;
      await page
        .getByRole('button', { name: 'Find databases', exact: true })
        .click();
      await page
        .getByLabel('Database', { exact: true })
        .selectOption({ label: '✅ Project tasks' });
      await page
        .getByRole('button', { name: 'Continue to sync setup', exact: true })
        .click();
      await expect(
        page
          .getByRole('main')
          .getByRole('heading', { name: /Notion rows/, level: 1 }),
      ).toBeVisible();
      expect(credentialBindings).toBe(1);
    });
  }

  test('Notion setup validates identifiers before storing credentials', async ({
    page,
  }) => {
    await page.route('**/integration-oauth/notion/list', route =>
      route.fulfill({ json: { configured: false, connections: [] } }),
    );
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    const secretWrites: string[] = [];
    page.on('request', request => {
      if (
        request.url().endsWith('/plugin-secret') &&
        request.method() === 'POST'
      )
        secretWrites.push(request.url());
    });
    await page.getByRole('link', { name: 'Integrations', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Notion', exact: true }),
    ).toBeVisible();
    await page.screenshot({
      path: '/tmp/atomic-integration-discovery.png',
      fullPage: true,
    });

    for (const disclosure of await page
      .locator('summary')
      .filter({ hasText: 'Repository test results' })
      .all()) {
      await disclosure.click();
    }

    await expect(
      page.getByText('Offline checks passed:', { exact: false }),
    ).toHaveCount(3);
    await expect(
      page.getByText('Live provider checks are not included in these results.'),
    ).toHaveCount(3);
    await page
      .locator('details')
      .filter({ hasText: 'Repository test results' })
      .last()
      .screenshot({ path: '/tmp/atomic-integration-evidence.png' });
    await expect(
      page.getByLabel('Data source ID', { exact: true }),
    ).toHaveCount(0);
    await page
      .locator('[data-integration=notion]')
      .getByRole('button', { name: 'Set up connection' })
      .click();
    await page
      .getByText('Advanced setup with a token', { exact: true })
      .click();
    const manual = page.locator('details').filter({
      has: page.getByText('Advanced setup with a token', { exact: true }),
    });
    await manual
      .getByRole('button', { name: 'Connect Notion', exact: true })
      .click();
    await expect(page.getByRole('alert')).toContainText('Enter');
    await page.getByLabel('Data source ID', { exact: true }).fill('../pages');
    await page
      .getByLabel('Notion connection token', { exact: true })
      .fill('local-validation-only');
    await manual
      .getByRole('button', { name: 'Connect Notion', exact: true })
      .click();
    await expect(
      page.getByRole('alert').filter({ hasText: 'UUID' }),
    ).toBeVisible();
    expect(secretWrites).toEqual([]);
    // A rejected setup request must remain visible, and the user can retry.
    await page.route('**/plugin-secret', route =>
      route.fulfill({
        status: 503,
        body: 'Setup temporarily unavailable',
      }),
    );
    await page
      .getByLabel('Data source ID', { exact: true })
      .fill('11111111-1111-4111-8111-111111111111');
    await page
      .getByLabel('Notion connection token', { exact: true })
      .press('Enter');
    await expect(page.getByRole('alert')).toContainText(
      'Could not store Notion credential',
    );
    await expect(
      manual.getByRole('button', { name: 'Connect Notion', exact: true }),
    ).toBeEnabled();
    expect(errors).toEqual([]);
    await page.screenshot({
      path: '/tmp/atomic-notion-store.png',
      fullPage: true,
    });
  });

  test('Clockify discovers named workspaces and surfaces preview transport errors', async ({
    page,
  }) => {
    await page.route('**/plugin-run', route => {
      const body = route.request().postDataJSON();
      if (JSON.parse(body.input).phase !== 'discover')
        return route.abort('failed');

      return route.fulfill({
        json: {
          error: null,
          verdict: JSON.stringify({
            intents: [],
            problems: [],
            discovery: {
              user: { id: 'bbbbbbbbbbbbbbbbbbbbbbbb', name: 'Test Person' },
              workspaces: [
                { id: 'aaaaaaaaaaaaaaaaaaaaaaaa', name: 'Test workspace' },
              ],
            },
          }),
        },
      });
    });
    await page.getByRole('link', { name: 'Integrations', exact: true }).click();
    await page
      .locator('[data-integration=clockify]')
      .getByRole('button', { name: 'Set up connection' })
      .click();
    await page.getByRole('button', { name: 'Find my workspaces' }).click();
    await expect(page.getByRole('alert')).toContainText(
      'Enter your Clockify API key',
    );
    await page
      .getByLabel('Clockify API key', { exact: true })
      .fill('synthetic-clockify-key');
    await page.getByRole('button', { name: 'Find my workspaces' }).click();
    await expect(page.getByLabel('Workspace', { exact: true })).toContainText(
      'Test workspace',
    );
    await expect(page.getByLabel('Import my completed entries')).toHaveValue(
      '7',
    );
    await page
      .getByRole('button', { name: 'Preview import', exact: true })
      .click();
    await expect(page.getByText(/Could not run this plugin/)).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Preview import', exact: true }),
    ).toBeEnabled();
  });

  test('Clockify applies linked entries through the real sandbox and skips repeats', async ({
    page,
  }) => {
    // Replace only the provider transport inside the sandbox. Discovery, mapping,
    // runtime, planning, signed commits and the second run's DB query stay real.
    await createTableFromDialog(page, {
      template: /Time tracker/i,
      name: 'Shared time entries',
    });
    const tableUrl = page.url();
    const tableSubject = new URL(tableUrl).searchParams.get('subject')!;
    const originalViews = await page.evaluate(
      async ({ subject, property }) =>
        (await window.store!.getResource(subject)).get(property),
      { subject: tableSubject, property: dataBrowser.properties.tableViews },
    );
    const startProperty = await page.evaluate(async subject => {
      const table = await window.store!.getResource(subject);
      const row = await window.store!.getResource(
        table.get('https://atomicdata.dev/properties/classtype') as string,
      );

      for (const field of row.get(
        'https://atomicdata.dev/properties/recommends',
      ) as string[]) {
        const property = await window.store!.getResource(field);

        if (
          property.get('https://atomicdata.dev/properties/shortname') ===
          'work-start'
        ) {
          await property.set(
            'https://atomicdata.dev/properties/name',
            'Started working',
          );
          await property.save();

          return field;
        }
      }

      throw new Error('Time Tracker start property missing');
    }, tableSubject);
    const now = Date.now();
    const fixture = {
      user: { id: 'bbbbbbbbbbbbbbbbbbbbbbbb', name: 'Fixture Person' },
      workspaces: [
        { id: 'aaaaaaaaaaaaaaaaaaaaaaaa', name: 'Fixture workspace' },
      ],
      projects: [{ id: 'cccccccccccccccccccccccc', name: 'Fixture Project' }],
      entries: [
        {
          id: 'dddddddddddddddddddddddd',
          userId: 'bbbbbbbbbbbbbbbbbbbbbbbb',
          projectId: 'cccccccccccccccccccccccc',
          description: 'Clockify fixture work',
          billable: true,
          timeInterval: {
            start: new Date(now - 7200000).toISOString(),
            end: new Date(now - 3600000).toISOString(),
          },
        },
      ],
    };
    let appSubject = '';
    let importDrive = '';
    await page.route('**/plugin-run', async route => {
      const body = route.request().postDataJSON();
      appSubject = body.plugin;
      importDrive = body.drive;
      expect(body.source).toContain('function run(ctx) {');
      body.source = body.source.replace(
        'function run(ctx) {',
        `function run(realCtx) { const ctx = { ...realCtx, http: r => {
          if (r.method !== 'GET') throw new Error('Fixture refuses provider writes');
          const fixtures = ${JSON.stringify(fixture)};
          if (!fixtures[r.operation]) throw new Error('Unknown fixture operation');
          return {status:200, body:JSON.stringify(fixtures[r.operation])};
        }};`,
      );
      const response = await route.fetch({ postData: JSON.stringify(body) });
      await route.fulfill({ response });
    });
    await page.getByRole('link', { name: 'Integrations', exact: true }).click();
    await page
      .locator('[data-integration=clockify]')
      .getByRole('button', { name: 'Set up connection' })
      .click();
    await page
      .getByLabel('Clockify API key', { exact: true })
      .fill('synthetic-clockify-key');
    await page.getByRole('button', { name: 'Find my workspaces' }).click();
    await expect(page.getByLabel('Workspace', { exact: true })).toContainText(
      'Fixture workspace',
    );
    await expect(page.getByLabel('Import into', { exact: true })).toContainText(
      'Shared time entries',
    );
    await page
      .getByLabel('Import into', { exact: true })
      .selectOption(tableSubject);
    await page
      .getByRole('button', { name: 'Preview import', exact: true })
      .click();
    await expect(
      page.getByRole('button', { name: 'Apply 3 changes', exact: true }),
    ).toBeEnabled();
    await page
      .getByRole('button', { name: 'Apply 3 changes', exact: true })
      .click();
    await expect(
      page.getByText('Applied 3 changes', { exact: true }),
    ).toBeVisible();
    const children = await page.evaluate(async parent => {
      const url = new URL('/query', window.store!.getServerUrl());
      url.searchParams.set(
        'property',
        'https://atomicdata.dev/properties/parent',
      );
      url.searchParams.set('value', parent);
      url.searchParams.set('include_nested', 'false');
      const result = await window.store!.fetchResourceFromServer(
        url.toString(),
        { noWebSocket: true, forceOverride: true },
      );
      const members = result.get(
        'https://atomicdata.dev/properties/collection/members',
      ) as string[];

      return Promise.all(
        members.map(async subject => ({
          subject,
          name: (await window.store!.getResource(subject)).title,
        })),
      );
    }, appSubject);
    expect(children.map(child => child.name)).toEqual(
      expect.arrayContaining(['Fixture Project', 'Fixture Person']),
    );
    // Simulate a previously imported record at the old default location.
    const projectSubject = children.find(
      child => child.name === 'Fixture Project',
    )!.subject;
    await page.evaluate(
      async ({ subject, drive }) => {
        const project = await window.store!.getResource(subject);
        await project.set('https://atomicdata.dev/properties/parent', drive);
        await project.save();
      },
      { subject: projectSubject, drive: importDrive },
    );
    await page
      .getByRole('button', { name: 'Preview import', exact: true })
      .click();
    await expect(
      page.getByRole('button', { name: 'Apply 1 changes', exact: true }),
    ).toBeEnabled();
    await expect(
      page.getByText(
        /previously imported root records will move inside this app/,
      ),
    ).toBeVisible();
    await page
      .getByRole('button', { name: 'Apply 1 changes', exact: true })
      .click();
    await expect(
      page.getByText('Applied 1 changes', { exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        async subject =>
          (await window.store!.getResource(subject)).get(
            'https://atomicdata.dev/properties/parent',
          ),
        projectSubject,
      ),
    ).toBe(appSubject);
    await page
      .getByRole('button', { name: 'Preview import', exact: true })
      .click();
    await expect(
      page.getByText('This run proposes no changes.', { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Apply 0 changes', exact: true }),
    ).toBeDisabled();
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    await page.evaluate(async subject => {
      const resource = await window.store!.getResource(subject);
      await resource.set(
        'https://atomicdata.dev/properties/name',
        'My project name',
      );
      await resource.save();
    }, projectSubject);

    for (const choice of ['Keep my value', 'Use source value']) {
      fixture.projects[0].name =
        choice === 'Keep my value'
          ? 'Remote project name'
          : 'New remote project name';
      await page
        .getByRole('button', { name: 'Preview import', exact: true })
        .click();
      await expect(
        page.getByText('Your value: "My project name"', { exact: true }),
      ).toBeVisible();
      await page.getByRole('button', { name: choice, exact: true }).click();
      await expect(
        page.getByText(
          'Resolution saved. Close this dialog and preview the import again.',
          { exact: true },
        ),
      ).toBeVisible();
      await page.getByRole('button', { name: 'Close', exact: true }).click();
      await page
        .getByRole('button', { name: 'Preview import', exact: true })
        .click();
      await expect(
        page.getByText('This run proposes no changes.', { exact: true }),
      ).toBeVisible();
      await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    }

    await expect(
      page.getByRole('button', { name: 'Manage import', exact: true }),
    ).toBeVisible();
    await page
      .getByRole('button', { name: 'Open time entries', exact: true })
      .click();
    await expect(
      page.getByRole('heading', { name: 'Shared time entries', exact: true }),
    ).toBeVisible();
    const afterViews = await page.evaluate(
      async ({ subject, property }) =>
        (await window.store!.getResource(subject)).get(property),
      { subject: tableSubject, property: dataBrowser.properties.tableViews },
    );
    expect(
      await page.evaluate(
        async subject =>
          (await window.store!.getResource(subject)).get(
            'https://atomicdata.dev/properties/name',
          ),
        startProperty,
      ),
    ).toBe('Started working');
    expect(afterViews).toEqual(originalViews);
    await expect(page.getByText('All entries', { exact: true })).toBeVisible();
    const originalSource = await page.evaluate(async subject => {
      const resource = await window.store!.getResource(subject);
      const entry = Object.entries(resource.getPropVals()).find(
        ([, value]) =>
          typeof value === 'string' && value.includes('const settings='),
      );
      if (!entry) throw new Error('Clockify source missing');
      await resource.set(entry[0], '// Previous release\n' + entry[1]);
      await resource.save();

      return { property: entry[0], source: entry[1] };
    }, appSubject);
    const pluginUrl = new URL(tableUrl);
    pluginUrl.searchParams.set('subject', appSubject);
    await page.goto(pluginUrl.href);
    await page.getByRole('tab', { name: 'Run', exact: true }).click();
    await page
      .getByRole('button', { name: 'Review Clockify update', exact: true })
      .click();
    await expect(
      page.getByText(
        /Your workspace, date range, destination table and stored key are kept/,
      ),
    ).toBeVisible();
    await page
      .getByRole('button', { name: 'Apply importer update', exact: true })
      .click();
    await expect(
      page.getByRole('button', { name: 'Review Clockify update', exact: true }),
    ).toHaveCount(0);
    expect(
      await page.evaluate(
        async ({ subject, property }) =>
          (await window.store!.getResource(subject)).get(property),
        { subject: appSubject, property: originalSource.property },
      ),
    ).toBe(originalSource.source);
  });

  test('GitHub reuses a task template table without replacing its views', async ({
    page,
  }) => {
    await createTableFromDialog(page, {
      template: /Project tasks/i,
      name: 'Shared project tasks',
    });
    const tableUrl = page.url();
    const tableSubject = new URL(tableUrl).searchParams.get('subject')!;
    const sharedProperties = await page.evaluate(async subject => {
      const table = await window.store!.getResource(subject);
      const klass = await window.store!.getResource(
        table.get('https://atomicdata.dev/properties/classtype') as string,
      );

      return klass.get('https://atomicdata.dev/properties/recommends');
    }, tableSubject);
    expect(sharedProperties).toEqual(
      expect.arrayContaining([
        'https://atomicdata.dev/task/v1/status',
        'https://atomicdata.dev/task/v1/body',
      ]),
    );
    await page.getByRole('link', { name: 'Integrations', exact: true }).click();
    await page
      .locator('[data-integration=github-issues]')
      .getByRole('button', { name: 'Set up connection' })
      .click();
    await page
      .getByRole('button', { name: 'Use a direct GitHub token instead' })
      .click();
    await expect(page.getByLabel('Sync into')).toContainText(
      'Shared project tasks',
    );
    await page
      .getByLabel('Sync into')
      .selectOption({ label: 'Shared project tasks' });
    await page
      .getByLabel('Repository', { exact: true })
      .fill('atomic-fixtures/shared-tasks');
    await page
      .getByLabel('GitHub token', { exact: true })
      .fill('local-install-test-token');
    await page
      .getByRole('button', { name: 'Connect GitHub', exact: true })
      .click();
    await expect(page).toHaveURL(tableUrl);
    await page.goto(tableUrl);
    await expect(
      page.getByRole('heading', { name: 'Shared project tasks', exact: true }),
    ).toBeVisible();
    await expect(page.getByText('Schedule', { exact: true })).toBeVisible();
  });

  test('GitHub can be installed from Integrations without a CLI', async ({
    page,
  }) => {
    const pageErrors: string[] = [];
    page.on('pageerror', e => pageErrors.push(e.message));
    await page.getByRole('link', { name: 'Integrations', exact: true }).click();
    await expect(page.getByLabel('GitHub token', { exact: true })).toHaveCount(
      0,
    );
    await page
      .getByRole('textbox', { name: 'Search integrations' })
      .fill('kanban');
    await expect(page.locator('[data-integration=notion]')).toHaveCount(0);
    await page
      .locator('[data-integration=github-issues]')
      .getByRole('button', { name: 'Set up connection' })
      .click();
    await page
      .getByRole('button', { name: 'Use a direct GitHub token instead' })
      .click();
    await page
      .getByLabel('Repository', { exact: true })
      .fill('atomic-fixtures/issues');
    await page
      .getByLabel('GitHub token', { exact: true })
      .fill('local-install-test-token');
    await page
      .getByRole('button', { name: 'Connect GitHub', exact: true })
      .click();
    await page
      .getByRole('button', { name: 'Connections', exact: true })
      .click();
    await page
      .getByRole('link', { name: 'Connection settings', exact: true })
      .click();
    await expect(
      page.getByRole('heading', {
        name: /GitHub issues: atomic-fixtures\/issues/,
      }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Preview sync', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Enable background sync', exact: true }),
    ).toBeDisabled();
    await page
      .getByLabel('Action', { exact: true })
      .selectOption('create_issue');
    await page
      .getByLabel('title', { exact: true })
      .fill('Synthetic issue for review');
    let approvalCalls = 0;
    await page.route('**/integration-action-approve', route => {
      approvalCalls++;

      return route.fulfill({ json: { status: 201, body: '{"number":42}' } });
    });
    const preparedResponse = page.waitForResponse(r =>
      r.url().endsWith('/integration-action-call'),
    );
    await page
      .getByRole('button', { name: 'Prepare for review', exact: true })
      .click();
    await expect(
      page.getByRole('button', { name: 'Approve action', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText(
        'Destination: https://api.github.com/repos/atomic-fixtures/issues/issues',
        { exact: true },
      ),
    ).toBeVisible();
    await page.screenshot({
      path: '/tmp/atomic-action-review.png',
      fullPage: true,
    });
    expect(approvalCalls).toBe(0);
    // Approval transport is stubbed: this browser test never writes to GitHub.
    await page
      .getByRole('button', { name: 'Approve action', exact: true })
      .click();
    await expect(
      page.getByText('{"number":42}', { exact: true }),
    ).toBeVisible();
    expect(approvalCalls).toBe(1);
    const prepared = (await (await preparedResponse).json()).proposal;
    await page
      .getByRole('button', { name: 'Prepare for review', exact: true })
      .click();
    await page
      .getByRole('button', { name: 'Cancel action', exact: true })
      .click();
    await page.getByText('Action history', { exact: true }).click();
    await expect(page.getByText('Cancelled', { exact: true })).toBeVisible();
    const callerSubject = await page.evaluate(async () => {
      const store = window.store;
      const connection = await store.getResource(
        new URL(location.href).searchParams.get('subject')!,
      );
      const drive = await store.getResource(
        connection.get('https://atomicdata.dev/properties/parent'),
      );
      const ontology = await store.getResource(
        drive.get(
          'https://atomicdata.dev/ontology/server/property/default-ontology',
        ),
      );
      const terms = await Promise.all(
        [
          ...(ontology.get('https://atomicdata.dev/properties/properties') ??
            []),
          ...(ontology.get('https://atomicdata.dev/properties/classes') ?? []),
        ].map(s => store.getResource(s)),
      );
      const term = (n: string) =>
        terms.find(
          r => r.get('https://atomicdata.dev/properties/shortname') === n,
        )!.subject;
      const caller = await store.newResource({
        parent: drive.subject,
        isA: [term('plugin-script')],
        propVals: {
          'https://atomicdata.dev/properties/name': 'Issue triage',
          [term('plugin-source')]:
            'export function run(ctx){return {intents:[]}}',
          [term('automation-integrations')]: [connection.subject],
        },
      });
      await caller.save();

      return caller.subject;
    });
    await page
      .getByText('Automation action permissions', { exact: true })
      .click();
    await expect(
      page.locator('#action-caller option').filter({ hasText: 'Issue triage' }),
    ).toHaveCount(1);
    await page
      .getByLabel('Automation', { exact: true })
      .selectOption({ label: 'Issue triage' });
    await page
      .getByLabel('Allowed action', { exact: true })
      .selectOption('create_issue');
    await page
      .getByLabel('Write approval', { exact: true })
      .selectOption('automatic');
    await page
      .getByRole('button', { name: 'Save action permission', exact: true })
      .click();
    await expect(
      page.getByText('create_issue — Automatic writes allowed', {
        exact: true,
      }),
    ).toBeVisible();
    await page
      .getByRole('button', { name: 'Revoke permission', exact: true })
      .click();
    await expect(
      page.getByRole('button', { name: 'Revoke permission', exact: true }),
    ).toHaveCount(0);
    // UI recovery uses a synthetic uncertain entry and read response. Host
    // recovery authorization and no-resend semantics are tested in Rust.
    let abandoned = false;
    let abandonCalls = 0;
    await page.route('**/integration-action-consumers', route =>
      route.fulfill({
        json: [
          {
            run: 'query:fixture',
            state: abandoned ? 'abandoned' : 'unfinished',
            audit: abandoned
              ? { at: Date.now(), reason: 'No longer needed' }
              : null,
          },
        ],
      }),
    );
    await page.route('**/integration-action-consumer-abandon', route => {
      expect(route.request().postDataJSON().reason).toBe('No longer needed');
      expect(route.request().postDataJSON().run).toBe('query:fixture');
      abandoned = true;
      abandonCalls++;

      return route.fulfill({ json: true });
    });
    let recovered = false;
    let confirmCalls = 0;
    await page.route('**/integration-action-history', route => {
      const older = !!route.request().postDataJSON().cursor;

      return route.fulfill({
        json: {
          entries: [
            {
              proposal: older
                ? { ...prepared, id: 'older', title: 'Earlier action' }
                : {
                    ...prepared,
                    origin: { caller: callerSubject, source_hash: 'fixture' },
                  },
              state: older
                ? 'cancelled'
                : recovered
                  ? 'completed'
                  : 'uncertain',
              receipt: null,
              resolution: null,
            },
          ],
          nextCursor: older ? null : 'older-page',
        },
      });
    });
    await page.route('**/integration-action-recovery-inspect', route =>
      route.fulfill({
        json: {
          receipt: {
            status: 200,
            body: '{"number":42,"title":"Synthetic issue for review"}',
          },
        },
      }),
    );
    await page.route('**/integration-action-recovery-confirm', route => {
      confirmCalls++;
      recovered = true;

      return route.fulfill({ json: true });
    });
    await expect(
      page.getByText('Outcome unknown — check the provider before continuing', {
        exact: true,
      }),
    ).toBeVisible();
    await page
      .getByRole('button', { name: 'Load more actions', exact: true })
      .click();
    await expect(
      page.getByRole('heading', { name: 'Earlier action', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Load more actions', exact: true }),
    ).toHaveCount(0);
    await page.getByText('Check and recover', { exact: true }).click();
    await page
      .getByLabel('Provider lookup', { exact: true })
      .selectOption('get_issue');
    await page.getByLabel('Positive issue number', { exact: true }).fill('42');
    await page
      .getByLabel('How does this record match the action?', { exact: true })
      .fill('Same issue title and creation time');
    await page
      .getByRole('button', { name: 'Look up provider result', exact: true })
      .click();
    await expect(
      page.getByRole('button', {
        name: 'I verified this is the action result',
        exact: true,
      }),
    ).toBeVisible();
    expect(confirmCalls).toBe(0);
    await page.screenshot({
      path: '/tmp/atomic-action-recovery.png',
      fullPage: true,
    });
    await page
      .getByRole('button', {
        name: 'I verified this is the action result',
        exact: true,
      })
      .click();
    await expect(page.getByText('Completed', { exact: true })).toBeVisible();
    expect(confirmCalls).toBe(1);
    await page
      .getByText('Automation runs using this action', { exact: true })
      .click();
    await page
      .getByRole('button', { name: 'Inspect consuming runs', exact: true })
      .click();
    await expect(
      page.getByRole('button', { name: 'Abandon this run', exact: true }),
    ).toBeDisabled();
    expect(abandonCalls).toBe(0);
    await page
      .getByLabel('Reason for abandoning this run', { exact: true })
      .fill('No longer needed');
    await page
      .getByRole('button', { name: 'Abandon this run', exact: true })
      .click();
    await expect(
      page.getByText('Abandoned by an operator', { exact: true }),
    ).toBeVisible();
    expect(abandonCalls).toBe(1);

    await page
      .getByText('Clean up old action details', { exact: true })
      .click();
    // First verify the real signed host endpoint on this fresh connection.
    await page
      .getByRole('button', { name: 'Preview cleanup', exact: true })
      .click();
    await expect(
      page.getByText('Checked 0 old actions; 0 eligible for cleanup.', {
        exact: true,
      }),
    ).toBeVisible();
    let cleanupWrites = 0;
    await page.route('**/integration-action-history-compact', route => {
      expect(route.request().postDataJSON().includeCompleted).toBe(true);
      expect(route.request().postDataJSON().includeAutomation).toBe(true);
      const apply = route.request().postDataJSON().apply === true;
      if (apply) cleanupWrites++;

      return route.fulfill({
        json: {
          scanned: 2,
          eligible: 1,
          compacted: apply ? 1 : 0,
          reclaimableBytes: 4096,
          nextCursor: null,
        },
      });
    });
    await page
      .getByRole('button', { name: 'Preview cleanup', exact: true })
      .click();
    await expect(
      page.getByText('Checked 2 old actions; 1 eligible for cleanup.', {
        exact: true,
      }),
    ).toBeVisible();
    expect(cleanupWrites).toBe(0);
    await page
      .getByRole('button', { name: 'Archive action details', exact: true })
      .click();
    await expect(
      page.getByText('Actions archived: 1', { exact: true }),
    ).toBeVisible();
    expect(cleanupWrites).toBe(1);

    await expect(
      page.getByLabel('What would you like to automate?'),
    ).not.toBeVisible();
    await page
      .getByText('Add an automation (optional)', { exact: true })
      .click();
    await expect(
      page.getByText('Excludes initial imports', { exact: false }),
    ).toBeVisible();
    await page.reload();
    await expect(
      page.getByRole('button', { name: 'Preview sync', exact: true }),
    ).toBeVisible();
    await page.route('**/chat/completions', route => route.abort());
    await page.route('https://openrouter.ai/api/v1/models', route =>
      route.fulfill({ json: { data: [] } }),
    );
    await page
      .getByText('Add an automation (optional)', { exact: true })
      .click();
    await page
      .getByLabel('What would you like to automate?')
      .fill('Triage bug reports for our team');
    await page
      .getByRole('button', { name: 'Build with Atomic assistant', exact: true })
      .click();
    await expect(page.getByTestId('ai-sidebar')).toBeVisible();
    await expect(page.getByTestId('ai-sidebar')).toContainText(
      'Triage bug reports for our team',
    );
    await expect(page.getByTestId('ai-sidebar')).toContainText(
      'GitHub issues: atomic-fixtures/issues',
    );
    await expect(
      page.getByRole('textbox', { name: 'Automation JavaScript', exact: true }),
    ).not.toBeVisible();
    expect(pageErrors).toEqual([]);
    // Installation saves a private release and host-side credential. It must
    // not perform any provider writes or start syncing before review.
  });

  test('an integration opens from the sidebar and syncs through the server sandbox', async ({
    page,
  }) => {
    test.setTimeout(120_000);
    const pageErrors: string[] = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    await newPlugin(page);
    await setSource(
      page,
      `export const manifest = { schemaVersion: 1, secrets: [], operations: [] };
export async function run(ctx) {
  if (ctx.phase === 'preview') return {kind:'preview',proposal:{changes:[]},problems:[]};
  if (ctx.cursor === 'done') return {kind:'complete'};
  return {kind:'effect',effect:{kind:'checkpoint',id:'checkpoint',records:[]},cursor:'done'};
}`,
    );
    const original = page.url();
    await page.getByRole('tab', { name: 'Code', exact: true }).click();
    const publication = page.waitForResponse(
      r =>
        r.url().endsWith('/plugin-release') && r.request().method() === 'POST',
    );
    await page
      .getByRole('button', { name: 'Publish to integration store' })
      .click();
    const { id } = await (await publication).json();
    await page.goto(original);
    await page.getByRole('tab', { name: 'Code', exact: true }).click();
    await expect(
      page
        .getByRole('main')
        .getByRole('heading', { name: 'New plugin', level: 1 }),
    ).toBeVisible();
    await page.evaluate(
      async ({ release }) => {
        const store = window.store;
        if (!(await store.waitForServerConnected(10000)))
          throw new Error('Test server did not connect');
        const plugin = await store.getResource(
          new URL(location.href).searchParams.get('subject')!,
        );
        const drive = await store.getResource(
          plugin.get('https://atomicdata.dev/properties/parent'),
        );
        const ontology = await store.getResource(
          drive.get(
            'https://atomicdata.dev/ontology/server/property/default-ontology',
          ),
        );
        const properties = await Promise.all(
          ontology
            .get('https://atomicdata.dev/properties/properties')!
            .map((p: string) => store.getResource(p)),
        );
        const property = properties.find(
          p =>
            p.get('https://atomicdata.dev/properties/shortname') ===
            'plugin-connection',
        );
        if (!property) throw new Error('Missing plugin-connection property');
        const room = await store.newResource({
          parent: drive.subject,
          isA: ['https://atomicdata.dev/classes/ChatRoom'],
          propVals: {
            'https://atomicdata.dev/properties/name': 'Issue notifications',
          },
        });
        await room.save();
        await plugin.set('https://atomicdata.dev/properties/emoji', '🐙');
        await plugin.set(property.subject, {
          release,
          config: {},
          events: [
            {
              id: 'added',
              name: 'Issue added to Atomic',
              description: 'Includes initial imports.',
              filters: [
                {
                  property: 'https://atomicdata.dev/properties/parent',
                  value: plugin.subject,
                },
              ],
            },
          ],
        });
        await plugin.save();
        const saved = await store.fetchResourceFromServer(plugin.subject, {
          noWebSocket: true,
        });
        if (!saved.get(property.subject))
          throw new Error('Connection configuration was not persisted');
      },
      { release: id },
    );
    await expect(
      page.getByRole('button', { name: 'Preview sync' }),
    ).toBeVisible();
    await page
      .getByText('Add an automation (optional)', { exact: true })
      .click();
    await page
      .getByText('Advanced: write JavaScript yourself', { exact: true })
      .click();
    await expect(
      page.getByRole('heading', { name: 'Automations', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Create automation' }),
    ).toBeEnabled();
    await page.getByRole('button', { name: 'Preview sync' }).click();
    await expect(page.getByText('0 records')).toBeVisible();
    await page.getByRole('button', { name: 'Approve sync' }).click();
    await expect(
      page.getByText('Sync complete.', { exact: true }),
    ).toBeVisible();
    await page.getByRole('button', { name: 'Enable background sync' }).click();
    await page.reload();
    await expect(
      page.getByRole('button', { name: 'Pause background sync' }),
    ).toBeVisible();
    await page.getByRole('button', { name: 'Pause background sync' }).click();
    await expect(
      page.getByRole('button', { name: 'Enable background sync' }),
    ).toBeVisible();
    await page.screenshot({
      path: '/tmp/atomic-integration-connection.png',
      fullPage: true,
    });
    const target = await page.evaluate(async () => {
      const store = window.store;
      const plugin = await store.getResource(
        new URL(location.href).searchParams.get('subject')!,
      );

      return {
        plugin: plugin.subject,
        drive: plugin.get('https://atomicdata.dev/properties/parent') as string,
      };
    });
    const agent = await Agent.fromSecret(await getDevDriveSecret(page));
    const api = { getAgent: () => agent, getServerUrl: () => SERVER_URL };
    const reviewed = await getPluginSync(api, target);
    await page.getByRole('button', { name: 'Enable background sync' }).click();
    await expect(
      page.getByRole('button', { name: 'Pause background sync' }),
    ).toBeVisible();
    await page.getByRole('link', { name: 'Integrations', exact: true }).click();
    await page
      .locator(`[data-connection="${target.plugin}"]`)
      .getByRole('button', { name: 'Create automation', exact: true })
      .click();
    await page
      .getByRole('dialog')
      .getByText('Advanced: write JavaScript yourself', { exact: true })
      .click();
    await page
      .getByRole('dialog')
      .getByRole('button', { name: 'Create automation', exact: true })
      .click();
    await page.getByText('View or edit JavaScript', { exact: true }).click();
    await expect(
      page.getByRole('textbox', { name: 'Automation JavaScript' }),
    ).toBeVisible();
    const automationSubject = new URL(page.url()).searchParams.get('subject')!;
    const relationship = await page.evaluate(async () => {
      const store = window.store;
      const script = await store.getResource(
        new URL(location.href).searchParams.get('subject')!,
      );
      const values = script.getPropVals();

      return {
        parent: script.get('https://atomicdata.dev/properties/parent'),
        values: JSON.stringify(values),
        source: Object.values(values).find(
          v => typeof v === 'string' && v.includes('export function run'),
        ),
      };
    });
    expect(relationship.values).toContain(
      new URL(original).searchParams.get('subject'),
    );
    expect(relationship.parent).not.toBe(
      new URL(original).searchParams.get('subject'),
    );
    expect(relationship.source).toContain('ctx.trigger.subject');
    expect(relationship.source).not.toContain('New issue:');
    const code = `export const manifest = { schemaVersion: 1 };
export function run() { return { intents: [{ op: 'create', localId: 'sample', parent: ${JSON.stringify(target.drive)}, set: { 'https://atomicdata.dev/properties/name': 'Automation sample result' } }], problems: [] }; }`;
    await page
      .getByRole('textbox', { name: 'Automation JavaScript' })
      .fill(code);
    await page.getByRole('button', { name: 'Save and test sample' }).click();
    const sampleDialog = page.locator('dialog[open]');
    await expect(
      sampleDialog.getByText('Automation sample result'),
    ).toBeVisible();
    await sampleDialog.getByRole('button', { name: /Apply 1 change/ }).click();
    await expect(sampleDialog).toBeHidden();
    await page
      .getByRole('button', { name: 'Enable automatic execution' })
      .click();
    await expect(
      page.getByRole('button', { name: 'Require review', exact: true }),
    ).toBeVisible();
    await page
      .getByRole('button', { name: 'Require review', exact: true })
      .click();
    await expect(
      page.getByRole('button', {
        name: 'Enable automatic execution',
        exact: true,
      }),
    ).toBeVisible();
    await page
      .getByRole('heading', {
        name: 'Build with the Atomic assistant',
        exact: true,
      })
      .scrollIntoViewIfNeeded();
    await page.screenshot({
      path: '/tmp/atomic-automation-workspace.png',
      fullPage: true,
    });
    const automationURL = new URL(original);
    automationURL.searchParams.set('subject', automationSubject);
    await page.goto(automationURL.toString());
    await expect(
      page.getByRole('button', { name: 'Enable automatic execution' }),
    ).toBeVisible();
    await page.getByRole('link', { name: 'Integrations', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Your integrations', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('region', { name: 'Your integrations' }).getByText('🐙'),
    ).toBeVisible();
    await page.screenshot({
      path: '/tmp/atomic-integrations-sidebar.png',
      fullPage: true,
    });
    expect(pageErrors).toEqual([]);
    await page.context().close();

    try {
      await expect
        .poll(
          async () => {
            const session = await getPluginSync(api, target);

            return (
              session?.run !== reviewed?.run && session?.status === 'complete'
            );
          },
          { timeout: 90_000, intervals: [2000] },
        )
        .toBe(true);
    } finally {
      await pluginSyncSchedule(api, {
        ...target,
        run: '',
        interval_seconds: 0,
      });
    }
  });

  test('a plugin proposes changes, and nothing is written until you approve', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    // `New plugin` is search-only: it creates the drive's plugin schema on
    // first use, so it stays out of the default listing.
    await page.getByRole('button', { name: 'More' }).click();
    await page.getByPlaceholder(/filter/i).fill('plugin');
    await page.locator('[data-testid="menu-item-new-plugin"]').click();

    await expect(
      main.getByRole('heading', { name: 'New plugin', level: 1 }),
    ).toBeVisible();

    // The starter source is what an author (or an LLM) reads first.
    await expect(main.getByText('export function run(input)')).toBeVisible();

    // Run appears once the drive's plugin class resolves — the menu subscribes
    // to the ontology, so no reload is needed after the schema is created.
    await page.getByRole('button', { name: 'More' }).click();

    const runItem = page.locator('[data-testid="menu-item-run-plugin"]');
    await expect(runItem).toBeVisible();
    await runItem.click();

    // The run has already happened: it holds no authority, so only writing
    // needs consent. The dialog is that boundary.
    const dialog = page.locator('dialog[open]');
    // The op is rendered lowercase and uppercased in CSS; `exact` keeps it
    // from also matching "created without a class…".
    await expect(dialog.getByText('create', { exact: true })).toBeVisible();
    await expect(dialog.getByText('Made by a plugin')).toBeVisible();

    const apply = dialog.getByRole('button', { name: /Apply 1 change/ });
    await expect(apply).toBeEnabled();

    // Running wrote nothing: the log behind the dialog still has no runs.
    await expect(main.getByText('This plugin has not run yet.')).toBeVisible();

    await apply.click();
    await expect(dialog).toBeHidden();

    // Now there is exactly one run, and it says what it did.
    await expect(main.getByRole('heading', { name: 'Runs' })).toBeVisible();
    // The status is rendered lowercase and uppercased in CSS; `exact` keeps it
    // from also matching the "1 applied" summary beside it.
    await expect(main.getByText('applied', { exact: true })).toBeVisible();
    await expect(main.getByText(/1 applied, 1 problem/)).toBeVisible();

    // Expanding it links to the resource the run actually created.
    await main.getByRole('button', { name: 'expand' }).first().click();
    await expect(main.getByRole('link', { name: 'example' })).toBeVisible();
  });

  test('a run whose target does not exist is blocked, and writes nothing', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    await page.getByRole('button', { name: 'More' }).click();
    await page.getByPlaceholder(/filter/i).fill('plugin');
    await page.locator('[data-testid="menu-item-new-plugin"]').click();
    await expect(
      main.getByRole('heading', { name: 'New plugin', level: 1 }),
    ).toBeVisible();

    // Point the plugin at a resource that is not there. The source property is
    // drive-local, so it is found by its value rather than by a subject the
    // test would have to know — and only `window.store` is used, so this does
    // not couple the test to app module paths.
    await page.evaluate(async () => {
      const store = (
        window as unknown as {
          store: {
            getResource(s: string): Promise<{
              getPropVals(): Record<string, unknown>;
              set(p: string, v: unknown): Promise<void>;
              save(): Promise<unknown>;
            }>;
          };
        }
      ).store;

      const subject = decodeURIComponent(
        new URL(location.href).searchParams.get('subject')!,
      );
      const plugin = await store.getResource(subject);

      const sourceProp = Object.entries(plugin.getPropVals()).find(
        ([, value]) =>
          typeof value === 'string' && value.includes('export function run'),
      )?.[0];

      if (!sourceProp) throw new Error('plugin has no source property');

      await plugin.set(
        sourceProp,
        `export function run() {
          return {
            intents: [{ op: 'set', subject: 'https://example.com/ghost',
                        set: { 'https://atomicdata.dev/properties/name': 'nope' } }],
            problems: [],
          };
        }`,
      );
      await plugin.save();
    });

    await page.getByRole('button', { name: 'More' }).click();
    await page.locator('[data-testid="menu-item-run-plugin"]').click();

    const dialog = page.locator('dialog[open]');
    await expect(dialog.getByText(/does not exist/)).toBeVisible();
    await expect(dialog.getByRole('button', { name: /Apply/ })).toBeDisabled();

    // Cancelling a blocked run still records it: a refusal that leaves no
    // trace reads the same as a plugin that never ran.
    await dialog.getByRole('button', { name: 'Close' }).click();
    await expect(dialog).toBeHidden();

    await expect(main.getByText('blocked', { exact: true })).toBeVisible();
  });
  test('a plugin asks for the credentials it declares, and nothing else', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    await newPlugin(page);

    // The starter needs no credentials, so it says so rather than showing an
    // empty heading with nowhere to type.
    await expect(main.getByText(/asks for no credentials/)).toBeVisible();

    await setSource(
      page,
      `export const manifest = {
         secrets: [{ name: 'notion', origin: 'https://api.notion.com',
                     description: 'Notion integration token' }],
       };
       export function run(ctx) {
         ctx.http({ url: 'https://api.notion.com/v1/search',
                    headers: { Authorization: 'Bearer secret:notion' } });
         return { intents: [], problems: [] };
       }`,
    );

    // A declared secret is one labelled field: the name and origin come from
    // the plugin, so neither is retyped.
    await expect(main.getByText('Notion integration token')).toBeVisible();
    await expect(
      main.getByPlaceholder(/Paste the value for notion/),
    ).toBeVisible();
  });

  test('a secret used but not declared still has somewhere to go', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    await newPlugin(page);

    await setSource(
      page,
      `export function run(ctx) {
         ctx.http({ url: 'https://api.notion.com/v1/search',
                    headers: { Authorization: 'Bearer secret:tok' } });
         return { intents: [], problems: [] };
       }`,
    );

    // The author who forgot to declare is the one who cannot work out where to
    // enter it, so a slot appears anyway — with the origin read from the URL
    // rather than asked for.
    await expect(main.getByText(/sent only to/)).toBeVisible();
    await expect(main.getByText(/api\.notion\.com/).first()).toBeVisible();
    await expect(main.getByPlaceholder(/Value for tok/)).toBeVisible();
  });
});

async function newPlugin(page: import('@playwright/test').Page) {
  await page.getByRole('button', { name: 'More' }).click();
  await page.getByPlaceholder(/filter/i).fill('plugin');
  await page.locator('[data-testid="menu-item-new-plugin"]').click();
  await expect(
    page.getByRole('main').getByRole('heading', {
      name: 'New plugin',
      level: 1,
    }),
  ).toBeVisible();
}

/**
 * Replaces a plugin's source through `window.store`.
 *
 * The source property is drive-local and has no fixed subject, so it is found
 * by its value — which keeps the test off app module paths.
 */
async function setSource(
  page: import('@playwright/test').Page,
  source: string,
) {
  await page.evaluate(async (next: string) => {
    const store = (
      window as unknown as {
        store: {
          getResource(s: string): Promise<{
            getPropVals(): Record<string, unknown>;
            set(p: string, v: unknown): Promise<void>;
            save(): Promise<unknown>;
          }>;
        };
      }
    ).store;

    const subject = decodeURIComponent(
      new URL(location.href).searchParams.get('subject')!,
    );
    const plugin = await store.getResource(subject);

    const sourceProp = Object.entries(plugin.getPropVals()).find(
      ([, value]) =>
        typeof value === 'string' && value.includes('export function run'),
    )?.[0];

    if (!sourceProp) throw new Error('plugin has no source property');

    await plugin.set(sourceProp, next);
    await plugin.save();
  }, source);
}
