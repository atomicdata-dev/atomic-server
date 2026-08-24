import { describe, expect, it } from 'vitest';
import { createApp } from './plugin-app.js';
import { core, server } from './index.js';
import type { SchemaStore } from './plugin-schema.js';
import type { JSONValue } from './value.js';

/**
 * A store that remembers what was written, so the assertions can be about the
 * shape of the subtree rather than about which calls were made.
 */
function fakeStore() {
  const resources = new Map<string, Record<string, JSONValue>>();
  let minted = 0;

  const wrap = (subject: string) => ({
    subject,
    error: undefined,
    new: false,
    get: (property: string) => resources.get(subject)?.[property],
    set: async (property: string, value: JSONValue) => {
      resources.set(subject, {
        ...(resources.get(subject) ?? {}),
        [property]: value,
      });
    },
    // Issuing the app's key pushes its DID onto the app's read/write lists.
    push: (property: string, values: string[]) => {
      const existing = resources.get(subject) ?? {};
      const current = Array.isArray(existing[property])
        ? (existing[property] as string[])
        : [];
      resources.set(subject, {
        ...existing,
        [property]: [...current, ...values] as unknown as JSONValue,
      });
    },
    save: async () => undefined,
    destroy: async () => undefined,
    remove: () => undefined,
  });

  const store: SchemaStore = {
    // Signed in: issuing a key is something an agent does, and refusing when
    // signed out is one of `issueAccessAgent`'s own rules.
    getAgent: () => ({ subject: 'did:ad:agent:me' }),
    resources: new Map(),
    notifyResourceManuallyCreated: () => undefined,
    getResource: async (subject: string) => wrap(subject),
    newResource: async ({
      subject: given,
      parent,
      isA,
      propVals,
    }: {
      subject?: string;
      parent: string;
      isA: string[] | string;
      propVals: Record<string, JSONValue>;
    }) => {
      const subject = given ?? `local:minted-${++minted}`;
      resources.set(subject, {
        [core.properties.parent]: parent,
        [core.properties.isA]: isA as unknown as JSONValue,
        ...propVals,
      });

      return wrap(subject);
    },
  } as unknown as SchemaStore;

  // The drive needs an ontology for `ensureSchema` to have somewhere to put
  // the plugin vocabulary.
  resources.set('drive', {
    [server.properties.defaultOntology]: 'drive-ontology',
  });
  resources.set('drive-ontology', {
    [core.properties.classes]: [] as unknown as JSONValue,
    [core.properties.properties]: [] as unknown as JSONValue,
  });

  return { store, resources };
}

const SOURCE = 'export function view({ root }) { root.textContent = "hi"; }';

describe('createApp', () => {
  it('puts every part of the app under the app', async () => {
    const { store, resources } = fakeStore();

    const created = await createApp(store, {
      drive: 'drive',
      name: 'Habits',
      source: SOURCE,
    });

    // Sharing the app has to mean sharing its parts, and rights ascend the
    // parent chain — so this parentage IS the sharing model.
    expect(resources.get(created.ontology)?.[core.properties.parent]).toBe(
      created.app,
    );
    expect(resources.get(created.entrypoint)?.[core.properties.parent]).toBe(
      created.app,
    );
    expect(resources.get(created.app)?.[core.properties.parent]).toBe('drive');
  });

  it('gives the app its own ontology, not the drive’s', async () => {
    const { store, resources } = fakeStore();

    const created = await createApp(store, {
      drive: 'drive',
      name: 'Habits',
      source: SOURCE,
    });

    // Two apps that both invent a `Task` must not collide, and an app must be
    // copyable without leaving its schema behind.
    expect(created.ontology).not.toBe('drive-ontology');
    expect(resources.get(created.app)?.[server.properties.defaultOntology]).toBe(
      created.ontology,
    );
  });

  it('names its entry point only once that entry point exists', async () => {
    const { store, resources } = fakeStore();

    const created = await createApp(store, {
      drive: 'drive',
      name: 'Habits',
      source: SOURCE,
    });

    const entrypointProperty = Object.keys(
      resources.get(created.app) ?? {},
    ).find(key => resources.get(created.app)?.[key] === created.entrypoint);

    expect(entrypointProperty).toBeDefined();
    expect(resources.get(created.entrypoint)).toBeDefined();
  });

  it('gives the app an identity of its own', async () => {
    const { store, resources } = fakeStore();

    const created = await createApp(store, {
      drive: 'drive',
      name: 'Habits',
      source: SOURCE,
    });

    expect(created.agent).toMatch(/^did:ad:agent:/);
    expect(created.secret).toBeTruthy();

    // Not under the app: an app may write its own subtree, so its agent
    // resource kept there would be a public key the app could replace.
    expect(resources.get(created.agent)?.[core.properties.parent]).not.toBe(
      created.app,
    );
  });

  it('keeps its rows in a table, not a folder', async () => {
    const { store, resources } = fakeStore();

    const created = await createApp(store, {
      drive: 'drive',
      name: 'Habits',
      source: SOURCE,
    });

    // Structurally a table and a folder are the same — rows are children — so
    // the difference that matters is the row class and the display config a
    // Table carries. Those are what make the rows sortable and editable
    // outside the app.
    const table = resources.get(created.data);

    expect(table?.[core.properties.parent]).toBe(created.app);
    expect(table?.['https://atomicdata.dev/properties/classtype']).toBe(
      created.rowClass,
    );
  });

  it('puts the row class in the app’s own ontology', async () => {
    const { store, resources } = fakeStore();

    const created = await createApp(store, {
      drive: 'drive',
      name: 'Habits',
      source: SOURCE,
    });

    expect(resources.get(created.rowClass)?.[core.properties.parent]).toBe(
      created.ontology,
    );
    // Listed there too, or nothing reading the ontology would find it.
    expect(resources.get(created.ontology)?.[core.properties.classes]).toEqual([
      created.rowClass,
    ]);
  });

  it('carries the source it was given', async () => {
    const { store, resources } = fakeStore();

    const created = await createApp(store, {
      drive: 'drive',
      name: 'Habits',
      source: SOURCE,
    });

    expect(Object.values(resources.get(created.entrypoint) ?? {})).toContain(
      SOURCE,
    );
  });

  it('makes a shortname an ontology will accept', async () => {
    const { store, resources } = fakeStore();

    const created = await createApp(store, {
      drive: 'drive',
      name: '1Password vault!',
      source: SOURCE,
    });

    const shortname = resources.get(created.ontology)?.[
      core.properties.shortname
    ] as string;

    expect(shortname).toMatch(/^[a-z][a-z0-9-]*$/);
  });
});
