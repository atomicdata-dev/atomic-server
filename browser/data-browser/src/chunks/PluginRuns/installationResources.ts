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
) {
  const find = async () => {
    const ids = await readConnectionSubjects(
      store,
      drive,
      core.properties.localId,
      options.localId,
    );
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
