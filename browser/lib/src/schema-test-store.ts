import { core } from './ontologies/core.js';
import { propertyId } from './property-identity.js';
import { sortedJson } from './ontology-input.js';
import type { SchemaStore } from './plugin-schema.js';
import type { JSONValue } from './value.js';

/**
 * An in-memory {@link SchemaStore} for tests of `ensureOntology` and the JSON
 * Schema conversion. Derives the `atomic:prop:` subject of a content-addressed
 * property like the real store, and only finds resources that were saved.
 */

export const TEST_DRIVE = 'https://x/drive';

interface Stored {
  subject: string;
  props: Record<string, JSONValue>;
}

export function makeSchemaStore(): {
  store: SchemaStore;
  world: Record<string, Stored>;
  /** Saves that changed or created something. */
  saves: string[];
} {
  const world: Record<string, Stored> = {
    [TEST_DRIVE]: { subject: TEST_DRIVE, props: {} },
  };
  const pending: Record<string, Stored> = {};
  const saves: string[] = [];
  let n = 0;

  const wrap = (stored: Stored) => {
    let dirty = false;

    return {
      subject: stored.subject,
      get: (property: string) => stored.props[property],
      set: async (property: string, value: JSONValue) => {
        if (sortedJson(stored.props[property]) === sortedJson(value)) return;

        stored.props[property] = value;
        dirty = true;
      },
      save: async () => {
        if (pending[stored.subject]) {
          world[stored.subject] = pending[stored.subject];
          delete pending[stored.subject];
          saves.push(stored.subject);
        } else if (dirty) {
          saves.push(stored.subject);
        }

        dirty = false;
      },
    };
  };

  const store: SchemaStore = {
    findByLocalId: async (_drive, parent, localId) => {
      const hit = Object.values(world).find(
        r =>
          r.props[core.properties.parent] === parent &&
          r.props[core.properties.localId] === localId,
      );

      return hit ? wrap(hit) : undefined;
    },
    getResource: async subject => {
      const stored = world[subject] ?? pending[subject];

      if (!stored) throw new Error(`unknown resource ${subject}`);

      return wrap(stored);
    },
    newResource: async opts => {
      const shortname = opts.propVals[core.properties.shortname];
      const datatype = opts.propVals[core.properties.datatype];
      const subject = opts.contentAddressedProperty
        ? propertyId(opts.parent, String(shortname), String(datatype))
        : `${opts.parent}/created-${++n}`;

      if (world[subject]) return wrap(world[subject]);

      pending[subject] = {
        subject,
        props: {
          ...opts.propVals,
          [core.properties.parent]: opts.parent,
          [core.properties.isA]: opts.isA,
        },
      };

      return wrap(pending[subject]);
    },
  };

  return { store, world, saves };
}
