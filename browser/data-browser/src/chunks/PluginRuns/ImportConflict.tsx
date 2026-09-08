import { useState } from 'react';
import {
  useStore,
  resolveImportConflict,
  applyHostFromStore,
  type Problem,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { ResourceInline } from '../../views/ResourceInline/ResourceInline';

/** Resolves a field separately, then requires a fresh import preview. */
export function ImportConflict({ problem }: { problem: Problem }) {
  const store = useStore();
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState('');
  const conflict = problem.importConflict!;

  const resolve = async (choice: 'local' | 'source') => {
    setBusy(true);
    setError('');

    try {
      const resource = await store.getResource(problem.subject!);
      const current = resource.getPropVals();
      if (
        JSON.stringify(current[problem.property!]) !==
        JSON.stringify(conflict.current)
      )
        throw new Error(
          'This value changed after the preview. Close this dialog and preview again.',
        );
      await applyHostFromStore(store).set(
        resource.subject,
        resolveImportConflict(
          current,
          problem.property!,
          conflict.source,
          choice,
        ),
      );
      setDone(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Column gap='0.5rem'>
      <Row>
        <ResourceInline subject={problem.subject!} />
        <ResourceInline subject={problem.property!} />
      </Row>
      <div>Your value: {JSON.stringify(conflict.current) ?? 'Empty'}</div>
      <div>Source value: {JSON.stringify(conflict.source)}</div>
      {error && <p role='alert'>{error}</p>}
      {done ? (
        <p role='status'>
          Resolution saved. Close this dialog and preview the import again.
        </p>
      ) : conflict.appendOnly ? (
        <p>
          This statement changed an existing transaction. Check the statement
          and its bank reference before importing again.
        </p>
      ) : (
        <Row>
          <Button subtle disabled={busy} onClick={() => void resolve('local')}>
            Keep my value
          </Button>
          <Button disabled={busy} onClick={() => void resolve('source')}>
            Use source value
          </Button>
        </Row>
      )}
    </Column>
  );
}
