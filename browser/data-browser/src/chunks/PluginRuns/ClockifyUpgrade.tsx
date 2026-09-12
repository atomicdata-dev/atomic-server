import { useState } from 'react';
import { useStore, pinPluginRelease } from '@tomic/react';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import { setPluginSource } from './runScript';
import { clockifyUpgrade } from './clockifyUpgradeSource';
import bundle from '../../../../../integrations/clockify/plugin.js?raw';

export function ClockifyUpgrade({
  source,
  drive,
  plugin,
}: {
  source: string;
  drive: string;
  plugin: string;
}) {
  const store = useStore();
  const [review, setReview] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [pending, setPending] = useState<string>();
  const next = pending ?? clockifyUpgrade(source, bundle);
  if (!next) return null;

  const upgrade = async () => {
    setBusy(true);
    setError('');
    setPending(next);

    try {
      await setPluginSource(store, plugin, drive, next);
      await pinPluginRelease(store, { drive, plugin });
      setPending(undefined);
      setReview(false);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Column>
      <Button subtle onClick={() => setReview(!review)}>
        Review Clockify update
      </Button>
      {review && (
        <Column>
          <h2>Update the Clockify importer</h2>
          <p>
            Repeated imports will update unchanged local fields when Clockify
            changes, preserve your edits, and ask you to resolve conflicts.
            Shared source identities prevent duplicate imports on this server.
          </p>
          <p>
            This replaces the importer code, including any custom edits. Your
            workspace, date range, destination table and stored key are kept.
            Existing records are checked on the next preview.
          </p>
          <details>
            <summary>Replacement code</summary>
            <pre style={{ whiteSpace: 'pre-wrap' }}>{next}</pre>
          </details>
          {error && <p role='alert'>{error}</p>}
          <Button disabled={busy} onClick={() => void upgrade()}>
            {busy ? 'Updating…' : 'Apply importer update'}
          </Button>
        </Column>
      )}
    </Column>
  );
}
