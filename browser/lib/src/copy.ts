import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import type { Resource } from './resource.js';
import type { Store } from './store.js';
import type { AtomicValue, JSONValue } from './value.js';

const P = 'https://atomicdata.dev/properties/';

/** Who a resource is: a copy gets its own. */
export const IDENTITY_PROPS: readonly string[] = [
  core.properties.parent,
  `${P}drive`,
  `${P}genesis`,
  `${P}lastCommit`,
  `${P}createdAt`,
  server.properties.createdBy,
];

/**
 * Who may reach a resource. A copy must inherit these from the folder it lands
 * in, never from the original: copying them would carry e.g. a published
 * page's `read: [PUBLIC_AGENT]` grant into another drive.
 */
export const RIGHTS_PROPS: readonly string[] = [
  core.properties.read,
  core.properties.write,
  `${P}append`,
];

/** Never copied by {@link copyResource}; `isA` is set from the options. */
export const NON_COPIED_PROPS: ReadonlySet<string> = new Set<string>([
  ...IDENTITY_PROPS,
  ...RIGHTS_PROPS,
  core.properties.isA,
  core.properties.localId,
]);

export interface CopyResourceOptions {
  /** Parent of the copy; rights and drive follow from it. Not needed with `copy`. */
  parent?: string;
  /** Classes of the copy. Defaults to the original's. */
  classes?: string[];
  /** Extra properties to set on the copy, as is. */
  propVals?: Record<string, AtomicValue>;
  /** More properties to leave out, on top of {@link NON_COPIED_PROPS}. */
  exclude?: ReadonlySet<string>;
  /** Old to new subjects: references to a key are rewritten to its value. */
  subjects?: ReadonlyMap<string, string>;
  /** A copy minted earlier with `deferGenesis`, so its id was known up front. */
  copy?: Resource;
}

/**
 * Copies one resource under `options.parent` as a new genesis resource: the
 * property values (minus identity and rights, see {@link NON_COPIED_PROPS}),
 * with references rewritten through `options.subjects`, and the Loro body of
 * rich text, seeded so both bodies share history.
 *
 * Returns the unsaved copy and, for a Loro body, the original's version that
 * was seeded from. Saving is left to the caller, which may need to order it.
 */
export async function copyResource(
  store: Store,
  original: Resource,
  {
    parent,
    classes = original.getClasses(),
    propVals = {},
    exclude,
    subjects,
    copy,
  }: CopyResourceOptions,
): Promise<{ copy: Resource; version?: string }> {
  const rewrite = (value: AtomicValue): AtomicValue =>
    typeof value === 'string'
      ? (subjects?.get(value) ?? value)
      : Array.isArray(value)
        ? (value.map(v => rewrite(v as AtomicValue)) as AtomicValue)
        : value;

  const content = Object.entries(original.getPropVals()).filter(
    ([prop]) => !NON_COPIED_PROPS.has(prop) && !exclude?.has(prop),
  );
  // Without a Loro body the genesis is committed as soon as the resource is
  // created, so the content must go in then: a genesis with `isA` but without
  // its required properties is dropped by the outbox.
  const withContent = !copy && !original.hasLoroBody();
  const target =
    copy ??
    (await store.newResource({
      parent,
      isA: classes,
      deferGenesis: original.hasLoroBody(),
      propVals: withContent
        ? ({
            ...Object.fromEntries(content.map(([p, v]) => [p, rewrite(v)])),
            ...propVals,
          } as Record<string, JSONValue>)
        : undefined,
    }));

  const identity = target.getPropVals();
  let version: string | undefined;

  // A rich-text body lives in the Loro doc, not in propvals. Seeding overwrites
  // the copy's propvals with the original's, so re-assert the copy's own.
  if (original.hasLoroBody()) {
    version = target.seedLoroBodyFrom(original);

    for (const [prop, value] of Object.entries(identity)) {
      await target.set(prop, value as AtomicValue, false);
    }
  }

  if (!withContent) {
    for (const [prop, value] of content) {
      await target.set(prop, rewrite(value), false);
    }

    for (const [prop, value] of Object.entries(propVals)) {
      await target.set(prop, value, false);
    }
  }

  // The seeded body also brought the original's rights; drop what is not ours.
  const keep = new Set([
    ...Object.keys(identity),
    ...content.map(c => c[0]),
    ...Object.keys(propVals),
  ]);

  for (const prop of Object.keys(target.getPropVals())) {
    if (!keep.has(prop)) target.remove(prop);
  }

  return { copy: target, version };
}
