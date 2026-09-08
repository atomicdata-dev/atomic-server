/** Reviewed, non-destructive source identity grouping. Original subjects stay readable. */
export const IMPORT_RESOLUTION =
  'https://atomicdata.dev/properties/importResolution';
export const IMPORT_REFERENCE_REVIEW =
  'https://atomicdata.dev/properties/importReferenceReview';
const base = 'https://atomicdata.dev/properties/';
const ignored = new Set([
  '@id',
  ...[
    'subject',
    'loroUpdate',
    'lastCommit',
    'createdAt',
    'updatedAt',
    'createdBy',
    'modifiedAt',
    'modifiedBy',
    'genesis',
    'importResolution',
  ].map(p => base + p),
]);

export function importReviewSnapshot(
  row: Record<string, unknown>,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(row).filter(([key]) => !ignored.has(key)),
  );
}
export function equalImportValue(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) || Array.isArray(b))
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((v, i) => equalImportValue(v, b[i]))
    );
  const left = Object.entries(a),
    right = Object.keys(b);

  return (
    left.length === right.length &&
    left.every(
      ([key, value]) =>
        Object.hasOwn(b, key) &&
        equalImportValue(value, (b as Record<string, unknown>)[key]),
    )
  );
}
export interface ImportResolution {
  version: 1;
  id: string;
  canonical: string;
  members: Record<string, Record<string, unknown>>;
  supersedes: string[];
  choices?: Record<string, string>;
}
const pure = (s: string) => (s.startsWith('did:') ? s.split('?')[0] : s);

function marker(row: Record<string, unknown>): ImportResolution | undefined {
  const v = row[IMPORT_RESOLUTION] as ImportResolution | undefined;

  return v?.version === 1 &&
    typeof v.id === 'string' &&
    typeof v.canonical === 'string' &&
    v.members &&
    typeof v.members === 'object' &&
    Array.isArray(v.supersedes)
    ? v
    : undefined;
}

export function reviewImportResolution(
  rows: Record<string, Record<string, unknown>>,
  canonical: string,
  id: string,
  choices: Record<string, string> = {},
): ImportResolution {
  const entries = Object.entries(rows);
  if (entries.length < 2 || entries.length > 100 || !rows[canonical] || !id)
    throw new Error(
      'Review between two and 100 copies and choose one primary record',
    );
  const selected = rows[canonical];

  for (const [, row] of entries) {
    if (
      typeof selected[base + 'localId'] !== 'string' ||
      !equalImportValue(row[base + 'localId'], selected[base + 'localId']) ||
      !equalImportValue(row[base + 'parent'], selected[base + 'parent']) ||
      !equalImportValue(row[base + 'isA'], selected[base + 'isA'])
    )
      throw new Error(
        'Copies must have the same source identity, parent and classes',
      );
  }

  for (const [property, source] of Object.entries(choices)) {
    if (!canConsolidateImportProperty(property))
      throw new Error('This field is protected');
    if (!rows[source]) throw new Error('Choose a reviewed copy');
  }

  return {
    choices: Object.fromEntries(
      Object.entries(choices).map(([p, s]) => [p, pure(s)]),
    ),
    version: 1,
    id,
    canonical: pure(canonical),
    members: Object.fromEntries(
      entries.map(([subject, row]) => [
        pure(subject),
        importReviewSnapshot(row),
      ]),
    ),
    supersedes: entries
      .flatMap(([, row]) => (marker(row)?.id ? [marker(row)!.id] : []))
      .sort(),
  };
}
/** Undefined means unresolved. Never infer a winner from query ordering. */
export function resolvedImportSubject(
  rows: Record<string, Record<string, unknown>>,
): string | undefined {
  const entries = Object.entries(rows);
  if (entries.length === 1 && !entries[0][1][IMPORT_RESOLUTION])
    return entries[0][0];
  const winners = entries.filter(([subject, row]) => {
    const resolution = marker(row);
    if (
      !resolution ||
      resolution.canonical !== pure(subject) ||
      Object.keys(resolution.members).length !== entries.length
    )
      return false;

    return entries.every(([other, value]) => {
      const reviewed = resolution.members[pure(other)];
      if (!reviewed) return false;
      if (other === subject) return true;
      const otherMarker = marker(value);

      return (
        (!otherMarker || resolution.supersedes.includes(otherMarker.id)) &&
        equalImportValue(reviewed, importReviewSnapshot(value))
      );
    });
  });

  return winners.length === 1 ? winners[0][0] : undefined;
}

/** Core identity, permissions and importer metadata are never consolidated. */
export function canConsolidateImportProperty(property: string): boolean {
  return (
    !ignored.has(property) &&
    (!property.startsWith(base) ||
      property === base + 'name' ||
      property === base + 'description')
  );
}
export function consolidatedImportValues(
  decision: ImportResolution,
): Record<string, unknown> {
  const values = { ...decision.members[decision.canonical] };

  for (const [property, source] of Object.entries(decision.choices ?? {})) {
    if (!canConsolidateImportProperty(property))
      throw new Error('This field is protected');
    const member = decision.members[source];
    if (!member) throw new Error('Choose a reviewed copy');
    if (Object.hasOwn(member, property)) values[property] = member[property];
    else delete values[property];
  }

  return values;
}
