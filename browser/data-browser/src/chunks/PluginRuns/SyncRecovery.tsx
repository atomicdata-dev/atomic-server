import { useState } from 'react';
import {
  useStore,
  inspectExternalOperation,
  confirmExternalOperation,
  type PluginSyncSession,
  type ExternalOperationStatus,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import { Card } from '@components/Card';
import { InputStyled } from '@components/forms/InputStyles';

export function SyncRecovery({
  drive,
  plugin,
  session,
  onResolved,
}: {
  drive: string;
  plugin: string;
  session: PluginSyncSession;
  onResolved: () => void;
}) {
  const store = useStore();
  const [status, setStatus] = useState<ExternalOperationStatus | null>();
  const [receipt, setReceipt] = useState('');
  const [evidence, setEvidence] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const effect = session.pending?.effect;
  if (session.status !== 'error' || !effect) return null;
  const operation = {
    drive,
    plugin,
    release: session.release,
    run: session.run,
    intent: effect.id,
  };

  const inspect = async () => {
    setBusy(true);

    try {
      setStatus(await inspectExternalOperation(store, operation));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    setBusy(true);

    try {
      const parsed = JSON.parse(receipt);
      if (!Number.isInteger(parsed.status) || typeof parsed.body !== 'string')
        throw new Error(
          'Enter a receipt with a numeric status and string body.',
        );
      await confirmExternalOperation(store, operation, parsed, evidence);
      onResolved();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <Column gap='0.75rem'>
        <h3>Sync needs attention</h3>
        <p>
          The saved run is paused. Completed steps are kept when you resume.
        </p>
        {effect.kind === 'external' ? (
          <>
            <p>
              Check the provider before retrying an operation whose result is
              uncertain.
            </p>
            <code>
              {effect.request?.method} {effect.request?.url}
            </code>
            <Button subtle onClick={inspect} disabled={busy}>
              Inspect saved result
            </Button>
            {status === null && (
              <p>
                No write was recorded. Fix the reported error, then resume sync.
              </p>
            )}
            {status?.receipt && (
              <p>A response is saved. Resume sync to reuse it.</p>
            )}
            {status && !status.receipt && (
              <>
                <p>
                  The request may have succeeded. After verifying it with the
                  provider, record its response below. This does not send the
                  write again.
                </p>
                <label htmlFor='sync-receipt'>
                  Verified response (status and body JSON)
                </label>
                <textarea
                  id='sync-receipt'
                  value={receipt}
                  onChange={e => setReceipt(e.target.value)}
                />
                <label htmlFor='sync-evidence'>
                  How you verified the result
                </label>
                <InputStyled
                  id='sync-evidence'
                  value={evidence}
                  onChange={e => setEvidence(e.target.value)}
                />
                <Button
                  disabled={busy || !receipt || !evidence.trim()}
                  onClick={confirm}
                >
                  Record verified result and resume
                </Button>
              </>
            )}
          </>
        ) : (
          <p>
            An Atomic write or checkpoint needs inspection. Resume uses saved
            receipts and stops if a previous write is uncertain.
          </p>
        )}
        {error && <p role='alert'>{error}</p>}
      </Column>
    </Card>
  );
}
