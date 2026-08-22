import { core, findSchema, pluginSchema, type Store } from '@tomic/react';
import type { Allowance } from './hostStore';

/**
 * What a drive's owner has allowed an app to write beyond its own subtree.
 *
 * A grant lives on the **drive**, never under the app it is about. An app may
 * write its own subtree, so a grant kept there would be a permission the app
 * could widen for itself — and the first thing a hostile app would do is
 * grant itself the rest of the drive. Grants parented elsewhere are ignored
 * here rather than merely discouraged by convention.
 */
export async function readAllowance(
  store: Store,
  drive: string,
  app: string,
): Promise<Allowance> {
  const schema = await findSchema(store, drive, pluginSchema());
  const grantClass = schema.classes?.['plugin-grant'];
  const grantedTo = schema.properties?.['granted-to'];
  const mayWrite = schema.properties?.['may-write'];

  if (!grantClass || !grantedTo || !mayWrite) return { mayWrite: [] };

  const candidates = await store.search('', {
    filters: { [core.properties.isA]: grantClass, [grantedTo]: app },
    limit: 50,
  });

  const found: FoundGrant[] = [];

  for (const subject of candidates) {
    const grant = await store.getResource(subject);

    found.push({
      parent: grant.get(core.properties.parent) as string | undefined,
      grantedTo: grant.get(grantedTo) as string | undefined,
      mayWrite: grant.get(mayWrite),
    });
  }

  return allowanceFrom(found, drive, app);
}

/** One grant as read, before anything has decided whether it counts. */
export interface FoundGrant {
  parent: string | undefined;
  grantedTo: string | undefined;
  mayWrite: unknown;
}

/**
 * Which of the grants found actually widen this app, and to what.
 *
 * Separate from the fetching so the rules can be read — and tested — without
 * a store in the way. These are the rules:
 */
export function allowanceFrom(
  grants: FoundGrant[],
  drive: string,
  app: string,
): Allowance {
  const allowed: string[] = [];

  for (const grant of grants) {
    // A grant that is not a direct child of the drive is not a grant. An app
    // may write its own subtree, so one kept under the app is a permission
    // the app could have written for itself.
    if (grant.parent !== drive) continue;

    // Re-checked because `search` reads an index: a stale entry naming another
    // app must not widen this one.
    if (grant.grantedTo !== app) continue;

    if (!Array.isArray(grant.mayWrite)) continue;

    allowed.push(
      ...grant.mayWrite.filter((s): s is string => typeof s === 'string'),
    );
  }

  return { mayWrite: allowed };
}
