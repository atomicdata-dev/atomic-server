import { useState } from 'react';
import { ImportReferences } from './ImportReferences';
import {
  core,
  useStore,
  reviewImportResolution,
  importReviewSnapshot,
  equalImportValue,
  IMPORT_RESOLUTION,
  canConsolidateImportProperty,
  consolidatedImportValues,
  type JSONValue,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { ResourceInline } from '../../views/ResourceInline/ResourceInline';

/** A signed decision groups source identities; original records and links survive. */
export function ImportCollision({ subjects }: { subjects: string[] }) {
  const store = useStore();
  const [rows, setRows] = useState<Record<string, Record<string, unknown>>>();
  const [primary, setPrimary] = useState('');
  const [choices, setChoices] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);

  const load = async () => {
    setBusy(true);
    setError('');

    try {
      const records = await Promise.all(
        subjects.map(async subject => {
          const resource = await store.fetchResourceFromServer(subject);
          if (resource.error) throw resource.error;

          return [subject, resource.getPropVals()] as const;
        }),
      );
      setRows(Object.fromEntries(records));
      setPrimary('');
      setChoices({});
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    if (!rows || !primary) return;
    setBusy(true);
    setError('');

    try {
      const decision = reviewImportResolution(
        rows,
        primary,
        crypto.randomUUID(),
        choices,
      );
      const resource = await store.getResource(primary);
      const values = consolidatedImportValues(decision);

      for (const property of Object.keys(choices)) {
        if (Object.hasOwn(values, property))
          await resource.set(property, values[property] as JSONValue);
        else resource.remove(property);
      }

      await resource.set(IMPORT_RESOLUTION, decision as unknown as JSONValue);
      await resource.save();
      // Read a detached server result: merging into the optimistic cache would
      // mistake a queued/rejected local decision for a confirmed server write.
      const confirmed = await store.readServerSnapshot(primary);
      const saved = confirmed[IMPORT_RESOLUTION] as { id?: string } | undefined;
      if (saved?.id !== decision.id)
        throw new Error(
          'The server did not confirm this choice. Refresh the comparison and try again.',
        );
      setDone(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const fields = rows
    ? [
        ...new Set(
          Object.values(rows).flatMap(row =>
            Object.keys(importReviewSnapshot(row)),
          ),
        ),
      ].filter(
        property =>
          !Object.values(rows).every(row =>
            equalImportValue(row[property], Object.values(rows)[0][property]),
          ),
      )
    : [];

  return (
    <Column gap='0.5rem'>
      <strong>Duplicate source records</strong>
      {!done && (
        <p>
          Choose which copy future imports should update. Both originals, their
          history and existing links are kept. Choose values below to combine
          information in the primary record.
        </p>
      )}
      {subjects.map(subject => (
        <Row
          key={subject}
          role='group'
          aria-label={String(rows?.[subject][core.properties.name] ?? subject)}
        >
          {done && (
            <span>
              {subject === primary ? 'Primary record' : 'Original copy'}
            </span>
          )}
          <ResourceInline subject={subject} />
          {rows && !done && (
            <Button
              subtle
              disabled={busy}
              onClick={() => setPrimary(subject)}
              aria-pressed={primary === subject}
            >
              Use as primary
            </Button>
          )}
        </Row>
      ))}
      {rows && !done && (
        <>
          <strong>Different values</strong>
          {fields.length === 0 && <p>These copies have the same values.</p>}
          {fields.map(property => (
            <Column key={property} gap='0.25rem'>
              <ResourceInline subject={property} />
              {subjects.map(subject => (
                <div
                  key={subject}
                  role='group'
                  aria-label={`Value from ${String(rows[subject][core.properties.name] ?? subject)}`}
                >
                  <ResourceInline subject={subject} />:{' '}
                  {JSON.stringify(rows[subject][property]) ?? 'Empty'}
                  {canConsolidateImportProperty(property) && (
                    <Button
                      subtle
                      disabled={busy || !primary}
                      aria-pressed={(choices[property] ?? primary) === subject}
                      onClick={() =>
                        setChoices(previous => ({
                          ...previous,
                          [property]: subject,
                        }))
                      }
                    >
                      Use this value
                    </Button>
                  )}
                </div>
              ))}
            </Column>
          ))}
          <p>
            Fields without a choice keep the primary record’s value. If another
            copy changes offline, you will need to review the copies again.
          </p>
        </>
      )}
      {error && <p role='alert'>{error}</p>}
      {done ? (
        <>
          <p role='status'>
            Primary record saved. You can review links below or close this
            dialog and preview the import again.
          </p>
          <ImportReferences primary={primary} copies={subjects} />
        </>
      ) : (
        <Row>
          <Button subtle disabled={busy} onClick={() => void load()}>
            {rows ? 'Refresh comparison' : 'Review copies'}
          </Button>
          {rows && (
            <Button disabled={!primary || busy} onClick={() => void save()}>
              Save primary record
            </Button>
          )}
        </Row>
      )}
    </Column>
  );
}
