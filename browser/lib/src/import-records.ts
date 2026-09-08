import {
  resolvedImportSubject,
  IMPORT_RESOLUTION,
  IMPORT_REFERENCE_REVIEW,
} from './import-resolution.js';
/** Shared sandbox import mapping. No provider, DOM, network or Store dependencies. */
import type { Intent, Problem } from './plugin-run.js';
import type { JSONValue } from './value.js';

export const IMPORT_LOCAL_ID = 'https://atomicdata.dev/properties/localId';
export const IMPORT_BASELINE =
  'https://atomicdata.dev/properties/importBaseline';
const PARENT = 'https://atomicdata.dev/properties/parent';
const IS_A = 'https://atomicdata.dev/properties/isA';

export interface ImportRecord {
  localId: string;
  sourceId: string;
  parent: string;
  isA: string[];
  values: Record<string, JSONValue>;
  /** Append-only statements reject changed source data; merge imports preserve local edits. */
  mode?: 'append' | 'merge';
  /** Read-only bridge to older imports, scoped to the same destination. */
  legacy?: { property: string; value: string };
}
export interface ImportHost {
  query(property: string, value: string): string[];
  read(subject: string): Record<string, unknown>;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object')
    return (
      '{' +
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => JSON.stringify(k) + ':' + canonical(v))
        .join(',') +
      '}'
    );

  return JSON.stringify(value) ?? 'undefined';
}

const same = (a: unknown, b: unknown) => canonical(a) === canonical(b);
const pure = (subject: unknown) =>
  typeof subject === 'string' && subject.startsWith('did:')
    ? subject.split('?')[0]
    : subject;

/** Convert source records into ordinary reviewed intents with persistent localIds. */
export function importRecords(host: ImportHost, records: ImportRecord[]) {
  const intents: Intent[] = [],
    problems: Problem[] = [];
  const bindings = new Map<string, string>();
  const snapshots = new Map<string, Record<string, unknown>>();
  const pending = new Map(records.map(record => [record.localId, record]));
  if (pending.size !== records.length)
    throw new Error('Duplicate localId in import batch');
  const identities = new Set<string>();
  let unchanged = 0,
    created = 0,
    updated = 0;

  const read = (subject: string) => {
    if (!snapshots.has(subject)) snapshots.set(subject, host.read(subject));

    return snapshots.get(subject)!;
  };

  const resolve = (value: JSONValue): JSONValue => {
    if (typeof value === 'string' && value.startsWith('local:')) {
      const id = value.slice(6);
      if (!bindings.has(id))
        throw new Error(`Unknown import reference ${value}`);

      return bindings.get(id)!;
    }

    if (Array.isArray(value)) return value.map(resolve);
    if (value && typeof value === 'object')
      return Object.fromEntries(
        Object.entries(value).map(([k, v]) => [k, resolve(v)]),
      );

    return value;
  };

  const destinations = new Map<string, string>();

  while (pending.size) {
    let progress = false;

    for (const [id, record] of pending) {
      if (!record.sourceId || !id)
        throw new Error('Import records need sourceId and localId');
      if (
        record.parent.startsWith('local:') &&
        !bindings.has(record.parent.slice(6))
      )
        continue;
      const parent = resolve(record.parent) as string;
      destinations.set(id, parent);
      const key = canonical([pure(parent), record.sourceId]);
      if (identities.has(key))
        throw new Error(
          'Duplicate destination/source identity in import batch',
        );
      identities.add(key);
      let matches: string[] = [];

      if (!parent.startsWith('local:')) {
        const match = (property: string, value: string) =>
          host.query(property, value).filter(subject => {
            const row = read(subject);

            return (
              pure(row[PARENT]) === pure(parent) && same(row[property], value)
            );
          });
        matches = match(IMPORT_LOCAL_ID, record.sourceId);
        if (!matches.length && record.legacy)
          matches = match(record.legacy.property, record.legacy.value);
      }

      let unresolved = false;

      if (
        matches.length > 1 ||
        (matches[0] && read(matches[0])[IMPORT_RESOLUTION])
      ) {
        const resolved = resolvedImportSubject(
          Object.fromEntries(matches.map(subject => [subject, read(subject)])),
        );
        if (resolved) matches = [resolved];
        else unresolved = true;
      }

      if (unresolved) {
        problems.push({
          severity: 'error',
          message:
            'Multiple records represent the same source. Review both before importing again.',
          property: IMPORT_LOCAL_ID,
          importCollision: [...matches].sort(),
        });

        return {
          intents,
          problems,
          summary: { created: 0, updated: 0, unchanged: 0 },
        };
      }

      const subject = matches[0];

      if (subject) {
        const current = read(subject);
        const classes = current[IS_A];
        if (
          !Array.isArray(classes) ||
          record.isA.some(klass => !classes.includes(klass))
        )
          throw new Error('Import identity belongs to a different class');
        const persisted = current[IMPORT_LOCAL_ID];
        if (persisted !== undefined && persisted !== record.sourceId)
          throw new Error('Existing record belongs to another import identity');
      }

      bindings.set(id, subject ?? `local:${id}`);
      pending.delete(id);
      progress = true;
    }

    if (!progress) throw new Error('Import parent cycle');
  }

  for (const record of records) {
    for (const key of [
      PARENT,
      IS_A,
      IMPORT_LOCAL_ID,
      IMPORT_BASELINE,
      IMPORT_RESOLUTION,
      IMPORT_REFERENCE_REVIEW,
    ]) {
      if (key in record.values)
        throw new Error(
          'Source values cannot set import identity or baseline metadata',
        );
    }

    const values = resolve(record.values) as Record<string, JSONValue>;
    const subject = bindings.get(record.localId)!;

    if (subject.startsWith('local:')) {
      intents.push({
        op: 'create',
        localId: record.localId,
        parent: destinations.get(record.localId)!,
        isA: record.isA,
        set: {
          ...values,
          [IMPORT_LOCAL_ID]: record.sourceId,
          [IMPORT_BASELINE]: { values, previous: {} },
        },
      });
      created++;
      continue;
    }

    const current = read(subject);
    const baseline = current[IMPORT_BASELINE] as
      | { values?: Record<string, JSONValue> }
      | undefined;
    if (
      baseline &&
      (!baseline.values ||
        typeof baseline.values !== 'object' ||
        Array.isArray(baseline.values))
    )
      throw new Error('Invalid saved import baseline');
    const prior = baseline?.values;
    const next = { ...prior, ...values };
    const set: Record<string, JSONValue> = {};
    let conflict = false;

    for (const [property, incoming] of Object.entries(values)) {
      const changedAppendSource =
        !!prior && record.mode === 'append' && !same(prior[property], incoming);
      if (same(current[property], incoming) && !changedAppendSource) continue;

      if (
        !prior ||
        changedAppendSource ||
        (!same(current[property], prior[property]) &&
          !same(incoming, prior[property]))
      ) {
        problems.push({
          severity: 'error',
          subject,
          property,
          importConflict: {
            source: incoming,
            current: current[property] as JSONValue,
            previous: prior?.[property],
            appendOnly: record.mode === 'append',
          },
          message: prior
            ? 'Source and local values conflict; resolve this record before importing.'
            : 'Existing record has no import baseline and differs from the source; review it before adoption.',
        });
        conflict = true;
        continue;
      }

      // Source unchanged: preserve a local edit, without overwriting it on repeat.
      if (same(incoming, prior[property])) continue;
      set[property] = incoming;
    }

    if (conflict) continue;
    if (!same(prior, next))
      set[IMPORT_BASELINE] = { values: next, previous: prior ?? {} };
    if (current[IMPORT_LOCAL_ID] === undefined)
      set[IMPORT_LOCAL_ID] = record.sourceId;
    if (Object.keys(set).length) {
      intents.push({ op: 'set', subject, set });
      updated++;
    } else unchanged++;
  }

  return { intents, problems, summary: { created, updated, unchanged } };
}

/** Build an explicitly reviewed single-field resolution. The core validates the
 * observed value at commit time; saving does not unblock the old proposal. */
export function resolveImportConflict(
  current: Record<string, unknown>,
  property: string,
  source: JSONValue,
  choice: 'local' | 'source',
): Record<string, JSONValue> {
  if (
    [
      PARENT,
      IS_A,
      IMPORT_LOCAL_ID,
      IMPORT_BASELINE,
      IMPORT_RESOLUTION,
      IMPORT_REFERENCE_REVIEW,
    ].includes(property)
  )
    throw new Error('Cannot resolve import metadata as source data');
  const baseline = current[IMPORT_BASELINE] as
    | { values?: Record<string, JSONValue> }
    | undefined;
  const previous = baseline?.values ?? {};
  const observed =
    property in current
      ? { present: true, value: current[property] as JSONValue }
      : { present: false };

  return {
    ...(choice === 'source' ? { [property]: source } : {}),
    [IMPORT_BASELINE]: {
      values: { ...previous, [property]: source },
      previous,
      resolution: { [property]: { ...observed, choice } },
    },
  };
}

/** Share native identity with sync adapters while leaving their baselines intact. */
export function claimImportIdentity(
  host: ImportHost,
  parent: string,
  sourceId: string,
  subject?: string,
) {
  const matches = host
    .query(IMPORT_LOCAL_ID, sourceId)
    .filter(id => pure(host.read(id)[PARENT]) === pure(parent));
  if (matches.length > 1 || matches.some(id => pure(id) !== pure(subject)))
    throw new Error(
      'Import identity already exists; reconcile the binding before syncing',
    );
  const old = subject ? host.read(subject)[IMPORT_LOCAL_ID] : undefined;
  if (old !== undefined && old !== sourceId)
    throw new Error('Resource belongs to another import identity');

  return { [IMPORT_LOCAL_ID]: sourceId };
}
