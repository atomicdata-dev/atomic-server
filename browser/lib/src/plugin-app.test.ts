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
    get: (property: string) => resources.get(subject)?.[property],
    set: async (property: string, value: JSONValue) => {
      resources.set(subject, {
        ...(resources.get(subject) ?? {}),
        [property]: value,
      });
    },
    save: async () => undefined,
    destroy: async () => undefined,
    remove: () => undefined,
  });

  const store: SchemaStore = {
    getResource: async (subject: string) => wrap(subject),
    newResource: async ({ parent, isA, propVals }) => {
      const subject = `local:minted-${++minted}`;
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
