import { core } from './ontologies/core.js';
import type { Store } from './store.js';

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object')
    return `{${Object.entries(value)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`)
      .join(',')}}`;

  return JSON.stringify(value);
}

async function digest(value: unknown) {
  const bytes = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical(value)),
  );

  return Array.from(new Uint8Array(bytes), b =>
    b.toString(16).padStart(2, '0'),
  ).join('');
}

/** Scope a deterministic installer to an immutable input. New resources receive
 * stable identities; caller save/validation/approval semantics are unchanged.
 * Repeat the same traversal after a crash. Explicit identities (schema terms)
 * retain their own namespace. Never use this for interactive unrelated creates. */
export async function resumableInstallation(
  store: Store,
  drive: string,
  installation: string,
  input: unknown,
): Promise<Store> {
  const prefix = `installation:${installation}:${await digest(input)}`;
  const occurrences = new Map<string, number>();

  return new Proxy(store, {
    get(target, property) {
      if (property === 'newResource')
        return async (
          options: NonNullable<Parameters<Store['newResource']>[0]>,
        ) => {
          if (options.propVals?.[core.properties.localId])
            return target.newResource(options);
          if (!options.parent)
            throw new Error(
              'Resumable installation resources need an explicit parent',
            );
          const label =
            options.propVals?.[core.properties.shortname] ??
            options.propVals?.[core.properties.name];
          // Generated subjects and cosmetic defaults (e.g. random tag colors)
          // are not logical identity. The immutable input already fingerprints
          // the full requested spec; duplicates retain traversal occurrence IDs.
          const hash = await digest({
            parent: options.parent,
            isA: options.isA,
            ...(label === undefined ? { values: options.propVals } : { label }),
          });
          const occurrence = occurrences.get(hash) ?? 0;
          occurrences.set(hash, occurrence + 1);
          const localId = `${prefix}:${hash}:${occurrence}`;
          const existing = await target.findByLocalId(
            drive,
            options.parent!,
            localId,
          );
          if (existing) return existing;

          return target.newResource({
            ...options,
            propVals: {
              ...options.propVals,
              [core.properties.localId]: localId,
            },
          });
        };

      const value = Reflect.get(target, property, target);

      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}
