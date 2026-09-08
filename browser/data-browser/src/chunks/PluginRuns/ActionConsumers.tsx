import { useId, useState } from 'react';
import { useStore } from '@tomic/react';
import {
  integrationActionConsumers,
  abandonIntegrationConsumer,
  type ActionConsumer,
} from '@tomic/lib';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import { BasicSelect } from '@components/forms/BasicSelect';
import { InputStyled } from '@components/forms/InputStyles';

export function ActionConsumers({
  drive,
  plugin,
  id,
}: {
  drive: string;
  plugin: string;
  id: string;
}) {
  const store = useStore();
  const field = useId();
  const [runs, setRuns] = useState<ActionConsumer[]>();
  const [run, setRun] = useState('');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const selected = runs?.find(r => r.run === run);

  const load = async (abandon = false) => {
    setBusy(true);
    setError(undefined);

    try {
      if (abandon)
        await abandonIntegrationConsumer(
          store,
          { drive, plugin },
          id,
          run,
          reason,
        );
      const result = await integrationActionConsumers(
        store,
        { drive, plugin },
        id,
      );
      setRuns(result);
      setRun(previous =>
        result.some(r => r.run === previous)
          ? previous
          : (result[0]?.run ?? ''),
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <details>
      <summary>Automation runs using this action</summary>
      <Column gap='0.5rem'>
        <Button disabled={busy} onClick={() => void load()}>
          Inspect consuming runs
        </Button>
        <Column>
          {runs && runs.length === 0 && (
            <p>
              No tracked runs. This action remains protected from automation
              cleanup.
            </p>
          )}
        </Column>
        <Column>
          {runs && runs.length > 0 && (
            <>
              <label htmlFor={field}>Consuming run</label>
              <BasicSelect
                id={field}
                value={run}
                onChange={e => {
                  setRun(e.target.value);
                  setReason('');
                }}
              >
                {runs.map(r => (
                  <option key={r.run} value={r.run}>
                    {r.run}
                  </option>
                ))}
              </BasicSelect>
              <p>
                {selected?.state === 'abandoned'
                  ? 'Abandoned by an operator'
                  : selected?.state === 'completed'
                    ? 'Completed'
                    : 'Unfinished — keeps this action available'}
              </p>
              <Column>
                {selected?.audit && (
                  <p>
                    {new Date(selected.audit.at).toLocaleString()}{' '}
                    {selected.audit.reason}
                  </p>
                )}
              </Column>
              <Column>
                {selected?.state === 'unfinished' && (
                  <>
                    <p>
                      Abandon this run permanently. Existing effects remain, and
                      future scheduled runs stay enabled. Uncertain provider
                      results still need reconciliation.
                    </p>
                    <label htmlFor={`${field}-reason`}>
                      Reason for abandoning this run
                    </label>
                    <InputStyled
                      id={`${field}-reason`}
                      value={reason}
                      maxLength={8192}
                      onChange={e => setReason(e.target.value)}
                    />
                    <Button
                      disabled={busy || !reason.trim()}
                      onClick={() => void load(true)}
                    >
                      Abandon this run
                    </Button>
                  </>
                )}
              </Column>
            </>
          )}
        </Column>
        <Column>{error && <p role='alert'>{error}</p>}</Column>
      </Column>
    </details>
  );
}
