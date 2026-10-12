import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import type { SchemaStore } from './plugin-schema.js';
import type { JSONValue } from './value.js';

/**
 * A store that remembers what was written, so the assertions can be about the
 * shape of the subtree rather than about which calls were made.
 */
export function fakeSchemaStore(): {
  store: SchemaStore;
  resources: Map<string, Record<string, JSONValue>>;
} {
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
    findByLocalId: async (_drive: string, parent: string, id: string) => {
      const entry = [...resources.entries()].find(
        ([, values]) =>
          values[core.properties.parent] === parent &&
          values[core.properties.localId] === id,
      );

      return entry ? wrap(entry[0]) : undefined;
    },
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
