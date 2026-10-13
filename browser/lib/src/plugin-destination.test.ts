import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { core, dataBrowser } from './index.js';
import {
  destinationTablesFor,
  provisionDestination,
} from './plugin-destination.js';
import { pluginSchema } from './plugin-log.js';
import { validateManifest } from './plugin-manifest.js';
import { findSchema } from './plugin-schema.js';
import { fakeSchemaStore } from './test-schema-store.js';

/** The shared manifest fixtures, as both manifest parsers accept them. */
const destinationOf = (name: string) => {
  const manifest = validateManifest(
    JSON.parse(
      readFileSync(
        new URL(`../../../testdata/plugin-manifest/${name}`, import.meta.url),
        'utf8',
      ),
    ),
  );
  if (!manifest.destination) throw new Error(`${name} has no destination`);

  return manifest.destination;
};

function setup() {
  const fake = fakeSchemaStore();
  fake.resources.set('plugin', { [core.properties.parent]: 'drive' });

  const childrenOf = (parent: string) =>
    [...fake.resources.entries()].filter(
      ([, values]) => values[core.properties.parent] === parent,
    );

  const stored = async () => {
    const terms = await findSchema(fake.store, 'drive', pluginSchema());

    return fake.resources.get('plugin')?.[
      terms.properties!['plugin-schemas']
    ] as Record<string, unknown>;
  };

  return { ...fake, childrenOf, stored };
}

describe('provisionDestination', () => {
  it('keeps the config of a single-table destination unchanged', async () => {
    const { store, resources, childrenOf, stored } = setup();
    const destination = destinationOf('v2-accepts-destination.json');

    const config = await provisionDestination(
      store,
      'drive',
      'plugin',
      destination,
      'statements',
    );

    // Exactly the shape importers written against one table destructure.
    expect(Object.keys(config).sort()).toEqual([
      'properties',
      'rowClass',
      'table',
    ]);
    expect(Object.keys(config.properties)).toEqual(['statement-amount']);
    const tables = childrenOf('plugin');
    expect(tables).toHaveLength(1);
    const [subject, table] = tables[0];
    expect(config.table).toBe(subject);
    expect(table[core.properties.localId]).toBe('atomic:destination:table');
    expect(table[core.properties.classtype]).toBe(config.rowClass);
    expect(table[core.properties.name]).toBe('Statement lines');
    expect(await stored()).toEqual({ statements: config });
    expect(resources.get(config.rowClass!)?.[core.properties.shortname]).toBe(
      'statement-line',
    );
  });

  it('sets up every table of a multi-class destination', async () => {
    const { store, resources, childrenOf, stored } = setup();
    const destination = destinationOf('v2-destination-tables.json');

    const config = await provisionDestination(
      store,
      'drive',
      'plugin',
      destination,
      'money',
    );

    expect(Object.keys(config.tables ?? {})).toEqual([
      'statements',
      'closingBalances',
    ]);
    const tables = childrenOf('plugin');
    expect(tables.map(([subject]) => subject).sort()).toEqual(
      [
        config.table,
        config.tables!.statements.table,
        config.tables!.closingBalances.table,
      ].sort(),
    );

    const shortnameOf = (klass: string) =>
      resources.get(klass)?.[core.properties.shortname];
    expect(shortnameOf(config.rowClass!)).toBe('bank-transaction');
    expect(shortnameOf(config.tables!.statements.rowClass)).toBe(
      'bank-statement',
    );
    expect(shortnameOf(config.tables!.closingBalances.rowClass)).toBe(
      'closing-balance',
    );

    // Each table is its own: its own row class and default view, so
    // statements never show up as rows of the transactions table.
    const balances = resources.get(config.tables!.closingBalances.table)!;
    expect(balances[core.properties.name]).toBe('Closing balances');
    expect(balances[core.properties.classtype]).toBe(
      config.tables!.closingBalances.rowClass,
    );
    const [[view, viewValues]] = childrenOf(
      config.tables!.closingBalances.table,
    );
    expect(balances[dataBrowser.properties.tableDefaultView]).toBe(view);
    expect(viewValues[dataBrowser.properties.viewColumns]).toEqual([
      config.properties['balance-date'],
      config.properties['bank-amount'],
    ]);

    expect(await stored()).toEqual({ money: config });
  });

  it('sets up keyed tables without a primary table', async () => {
    const { store, childrenOf } = setup();

    const config = await provisionDestination(
      store,
      'drive',
      'plugin',
      destinationOf('v2-destination-tables-only.json'),
      undefined,
    );

    expect(config.table).toBeUndefined();
    expect(config.rowClass).toBeUndefined();
    expect(childrenOf('plugin')).toHaveLength(2);
  });

  it('resumes: repeating, or adding a table in a later release, creates only what is new', async () => {
    const { store, childrenOf } = setup();
    const first = await provisionDestination(
      store,
      'drive',
      'plugin',
      {
        ...destinationOf('v2-destination-tables.json'),
        tables: undefined,
      },
      'money',
    );
    expect(childrenOf('plugin')).toHaveLength(1);

    const second = await provisionDestination(
      store,
      'drive',
      'plugin',
      destinationOf('v2-destination-tables.json'),
      'money',
    );
    const again = await provisionDestination(
      store,
      'drive',
      'plugin',
      destinationOf('v2-destination-tables.json'),
      'money',
    );

    expect(second.table).toBe(first.table);
    expect(again).toEqual(second);
    expect(childrenOf('plugin')).toHaveLength(3);
  });
});

describe('destinationTablesFor', () => {
  it('lets an app shown on any of the tables find each one by its key', async () => {
    const { store } = setup();
    const config = await provisionDestination(
      store,
      'drive',
      'plugin',
      destinationOf('v2-destination-tables.json'),
      'money',
    );

    for (const table of [
      config.table!,
      config.tables!.statements.table,
      config.tables!.closingBalances.table,
    ])
      expect(await destinationTablesFor(store, 'drive', table)).toEqual(
        config.tables,
      );
  });

  it('finds keyed tables stored flat, without a config key', async () => {
    const { store } = setup();
    const config = await provisionDestination(
      store,
      'drive',
      'plugin',
      destinationOf('v2-destination-tables-only.json'),
      undefined,
    );

    expect(
      await destinationTablesFor(
        store,
        'drive',
        config.tables!.statements.table,
      ),
    ).toEqual(config.tables);
  });

  it('has nothing to add for a single-table destination or an unrelated table', async () => {
    const { store, resources } = setup();
    const config = await provisionDestination(
      store,
      'drive',
      'plugin',
      destinationOf('v2-accepts-destination.json'),
      'statements',
    );
    resources.set('elsewhere', { [core.properties.parent]: 'drive' });

    expect(
      await destinationTablesFor(store, 'drive', config.table!),
    ).toBeUndefined();
    expect(
      await destinationTablesFor(store, 'drive', 'elsewhere'),
    ).toBeUndefined();
  });
});
