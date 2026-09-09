// @wc-ignore-file
import {
  core,
  readConnectionSubjects,
  type Store,
  type JSONValue,
} from '@tomic/react';

/** Durable setup steps: query the authoritative server after a lost receipt. */
export async function ensureInstallationResource(
  store: Store,
  drive: string,
  options: {
    parent: string;
    localId: string;
    isA: string[];
    propVals: Record<string, JSONValue>;
  },
  local = false,
) {
  const find = async () => {
    const ids = await (
      local ? readLocalInstallationSubjects : readConnectionSubjects
    )(store, drive, core.properties.localId, options.localId);
    const resources = await Promise.all(ids.map(id => store.getResource(id)));
    const matches = resources.filter(
      r =>
        String(r.get(core.properties.parent)).split('?')[0] ===
        options.parent.split('?')[0],
    );
    if (matches.length > 1)
      throw new Error(
        'Duplicate installation identity; resolve it before retrying',
      );
    const resource = matches[0];
    if (
      resource &&
      options.isA.some(
        c =>
          !(
            resource.get(core.properties.isA) as string[] | undefined
          )?.includes(c),
      )
    )
      throw new Error('Installation identity belongs to a different class');

    return resource;
  };

  const existing = await find();
  if (existing) return existing;

  try {
    const resource = await store.newResource({
      ...options,
      propVals: {
        ...options.propVals,
        [core.properties.localId]: options.localId,
      },
    });
    await resource.save();

    return resource;
  } catch (error) {
    // A successful save with a lost response and a concurrent winner are both
    // recoverable. Network/query failures remain visible, never an empty result.
    const saved = await find();
    if (saved) return saved;
    throw error;
  }
}

async function readLocalInstallationSubjects(
  store: Store,
  drive: string,
  property: string,
  value: string,
) {
  const result = await store.queryLocalDb({
    drive,
    property,
    value,
    limit: 10001,
  });
  if (!result || result.count !== result.subjects.length)
    throw new Error(
      'Local installation query failed or is incomplete; refusing to create duplicates',
    );
  return result.subjects;
}

/** LocalThought installations use the same identity checks against local OPFS. */
export function ensureLocalInstallationResource(
  store: Store,
  drive: string,
  options: Parameters<typeof ensureInstallationResource>[2],
) {
  return ensureInstallationResource(store, drive, options, true);
}

/** Schema recovery must use the same local identity authority as installation. */
export function localSchemaStore(store: Store) {
  return {
    getResource: store.getResource.bind(store),
    newResource: store.newResource.bind(store),
    findByLocalId: async (drive: string, parent: string, localId: string) => {
      const subjects = await readLocalInstallationSubjects(
        store,
        drive,
        core.properties.localId,
        localId,
      );
      const resources = await Promise.all(
        subjects.map(s => store.getResource(s)),
      );
      const matches = resources.filter(
        r =>
          String(r.get(core.properties.parent)).split('?')[0] ===
          parent.split('?')[0],
      );
      if (matches.length > 1)
        throw new Error(
          'Duplicate local schema identity; resolve before importing',
        );
      return matches[0];
    },
  };
}
