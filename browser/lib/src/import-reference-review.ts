import { Datatype } from './datatypes.js';
import {
  equalImportValue,
  IMPORT_REFERENCE_REVIEW,
} from './import-resolution.js';

export interface ImportReferenceChange {
  subject: string;
  property: string;
  before: string | string[];
  after: string | string[];
}
/** Build a review from explicitly supplied, readable records and property types.
 * Does not inspect opaque JSON, text, hierarchy or security metadata.
 * This is a bounded preview, not a claim that every incoming link was found.
 */
export function reviewImportReferences(
  rows: Record<string, Record<string, unknown>>,
  datatypes: Record<string, string>,
  retained: string[],
  primary: string,
): ImportReferenceChange[] {
  const pure = (s: string) => (s.startsWith('did:') ? s.split('?')[0] : s);
  const copies = new Set(retained.map(pure));
  if (copies.has(pure(primary)))
    throw new Error('Primary cannot be a retained copy');
  const replace = (s: string) => (copies.has(pure(s)) ? primary : s);
  const changes: ImportReferenceChange[] = [];

  for (const [subject, row] of Object.entries(rows)) {
    // Decisions retain exact snapshots of all copies. Never rewrite those records.
    if (
      subject.startsWith('did:ad:commit:') ||
      copies.has(pure(subject)) ||
      pure(subject) === pure(primary)
    )
      continue;

    for (const [property, value] of Object.entries(row)) {
      if (property.startsWith('https://atomicdata.dev/properties/')) continue;
      let after: string | string[];
      if (
        datatypes[property] === Datatype.ATOMIC_URL &&
        typeof value === 'string'
      )
        after = replace(value);
      else if (
        datatypes[property] === Datatype.RESOURCEARRAY &&
        Array.isArray(value) &&
        value.every(v => typeof v === 'string')
      )
        after = value.map(replace);
      else continue;
      if (!equalImportValue(value, after))
        changes.push({
          subject,
          property,
          before: value as string | string[],
          after,
        });
    }
  }

  return changes;
}

export interface ImportReferenceHost {
  read(subject: string): Promise<Record<string, unknown>>;
  write(subject: string, values: Record<string, unknown>): Promise<void>;
}
export interface ImportReferenceOutcome {
  subject: string;
  status: 'confirmed' | 'needs-review';
  error?: string;
}
/** Re-read each record, persist a signed precondition, then confirm outside the
 * optimistic cache. A lost acknowledgement is recoverable by rerunning the same
 * plan: values already at the destination need no write. Never retry transport.
 */
export async function applyImportReferences(
  host: ImportReferenceHost,
  changes: ImportReferenceChange[],
): Promise<ImportReferenceOutcome[]> {
  const grouped = new Map<string, ImportReferenceChange[]>();
  for (const change of changes)
    grouped.set(change.subject, [
      ...(grouped.get(change.subject) ?? []),
      change,
    ]);
  const outcomes: ImportReferenceOutcome[] = [];

  for (const [subject, fields] of grouped) {
    try {
      const current = await host.read(subject);
      const pending = fields.filter(
        f => !equalImportValue(current[f.property], f.after),
      );
      for (const field of pending)
        if (!equalImportValue(current[field.property], field.before))
          throw new Error('Links changed since review. Refresh the review.');

      if (pending.length) {
        const id = crypto.randomUUID();

        try {
          await host.write(subject, {
            ...Object.fromEntries(pending.map(f => [f.property, f.after])),
            [IMPORT_REFERENCE_REVIEW]: {
              id,
              changes: pending.map(({ property, before, after }) => ({
                property,
                before,
                after,
              })),
            },
          });
        } catch (error) {
          // A failed acknowledgement is not proof that the write failed.
          const saved = await host.read(subject);
          if (!pending.every(f => equalImportValue(saved[f.property], f.after)))
            throw error;
        }
      }

      const confirmed = await host.read(subject);
      if (!fields.every(f => equalImportValue(confirmed[f.property], f.after)))
        throw new Error(
          'The server did not confirm these links. Refresh the review.',
        );
      outcomes.push({ subject, status: 'confirmed' });
    } catch (error) {
      outcomes.push({ subject, status: 'needs-review', error: String(error) });
    }
  }

  return outcomes;
}
