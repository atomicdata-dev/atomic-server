import { useState } from 'react';
import {
  useStore,
  core,
  readConnectionSubjects,
  reviewImportReferences,
  applyImportReferences,
  type ImportReferenceChange,
  type ImportReferenceOutcome,
  type JSONValue,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { ResourceInline } from '../../views/ResourceInline/ResourceInline';

export function ImportReferences({
  primary,
  copies,
}: {
  primary: string;
  copies: string[];
}) {
  const store = useStore();
  const [changes, setChanges] = useState<ImportReferenceChange[]>();
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [outcomes, setOutcomes] = useState<ImportReferenceOutcome[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const discover = async () => {
    setBusy(true);
    setError('');
    setChanges(undefined);
    setOutcomes([]);

    try {
      const drive = store.getDrive();
      if (!drive) throw new Error('Choose a drive first');
      const pure = (s: string) => (s.startsWith('did:') ? s.split('?')[0] : s);
      const retained = new Set(
        copies.map(pure).filter(s => s !== pure(primary)),
      );
      const found = new Set<string>();

      for (const copy of retained) {
        for (const subject of await readConnectionSubjects(
          store,
          drive,
          undefined,
          copy,
        ))
          found.add(subject);
      }

      const subjects = [...found].filter(s => !s.startsWith('did:ad:commit:'));
      if (subjects.length > 1000)
        throw new Error(
          'More than 1,000 records link to these copies. Review a smaller group of copies.',
        );
      const rows: Record<string, Record<string, unknown>> = {};

      for (let offset = 0; offset < subjects.length; offset += 10) {
        await Promise.all(
          subjects.slice(offset, offset + 10).map(async subject => {
            rows[subject] = await store.readServerSnapshot(subject);
          }),
        );
      }

      // Fetch types only for properties which actually contain one of the copies.
      const properties = new Set(
        Object.values(rows).flatMap(row =>
          Object.entries(row)
            .filter(
              ([p, value]) =>
                !p.startsWith('https://atomicdata.dev/properties/') &&
                (Array.isArray(value) ? value : [value]).some(
                  v => typeof v === 'string' && retained.has(pure(v)),
                ),
            )
            .map(([p]) => p),
        ),
      );
      const datatypes: Record<string, string> = {};

      for (const property of properties) {
        const resource = await store.readServerSnapshot(property);
        datatypes[property] = String(resource[core.properties.datatype]);
      }

      const plan = reviewImportReferences(
        rows,
        datatypes,
        copies.filter(s => s.split('?')[0] !== primary.split('?')[0]),
        primary,
      );
      setChanges(plan);
      setSelected(new Set(plan.map((_, i) => i)));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    if (!changes) return;
    setBusy(true);
    setError('');

    try {
      const source = await store.readServerSnapshot(primary);
      const resolved = await store.findByLocalId(
        store.getDrive()!,
        String(source[core.properties.parent]),
        String(source[core.properties.localId]),
      );
      if (resolved?.subject.split('?')[0] !== primary.split('?')[0])
        throw new Error('The primary record changed. Review the copies again.');
      setOutcomes(
        await applyImportReferences(
          {
            read: async subject => store.readServerSnapshot(subject),
            write: async (subject, values) => {
              const resource = await store.fetchResourceFromServer(subject);
              if (resource.error) throw resource.error;
              for (const [property, value] of Object.entries(values))
                await resource.set(property, value as JSONValue);
              await resource.save();
            },
          },
          changes.filter((_, i) => selected.has(i)),
        ),
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Column gap='0.5rem'>
      <strong>Update links to the primary record</strong>
      <p>
        Optionally update links in records you can read in this drive. Original
        copies, hierarchy, text and history stay intact. Each record is saved
        separately.
      </p>
      <Button subtle disabled={busy} onClick={() => void discover()}>
        {changes ? 'Refresh link review' : 'Find links to these copies'}
      </Button>
      {changes?.length === 0 && <p>No supported links found in this drive.</p>}
      {changes?.map((change, index) => (
        <Column key={`${change.subject}:${change.property}`} gap='0.25rem'>
          <Row>
            <ResourceInline subject={change.subject} />
            <ResourceInline subject={change.property} />
            <Button
              subtle
              disabled={busy}
              aria-pressed={selected.has(index)}
              onClick={() =>
                setSelected(previous => {
                  const next = new Set(previous);
                  if (next.has(index)) next.delete(index);
                  else next.add(index);

                  return next;
                })
              }
            >
              {selected.has(index) ? 'Included' : 'Include'}
            </Button>
          </Row>
          <Row>
            <span>From original</span>
            {(Array.isArray(change.before)
              ? change.before
              : [change.before]
            ).map((s, i) => (
              <ResourceInline key={i} subject={s} />
            ))}
          </Row>
          <Row>
            <span>To primary</span>
            {(Array.isArray(change.after) ? change.after : [change.after]).map(
              (s, i) => (
                <ResourceInline key={i} subject={s} />
              ),
            )}
          </Row>
        </Column>
      ))}
      {!!changes?.length && (
        <Button disabled={busy || !selected.size} onClick={() => void apply()}>
          Update selected links
        </Button>
      )}
      {outcomes.map(outcome => (
        <Row key={outcome.subject}>
          <ResourceInline subject={outcome.subject} />
          <span role={outcome.status === 'confirmed' ? 'status' : 'alert'}>
            {outcome.status === 'confirmed' ? 'Links confirmed' : outcome.error}
          </span>
        </Row>
      ))}
      {error && <p role='alert'>{error}</p>}
      {busy && <p role='status'>Checking records…</p>}
    </Column>
  );
}
