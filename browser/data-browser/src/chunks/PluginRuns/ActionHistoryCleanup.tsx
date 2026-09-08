import { useState } from 'react';
import { useStore } from '@tomic/react';
import {
  compactIntegrationActionHistory,
  type ActionCompactionPage,
} from '@tomic/lib';
import { Button } from '@components/Button';
import { Column } from '@components/Row';

export function ActionHistoryCleanup({
  drive,
  plugin,
}: {
  drive: string;
  plugin: string;
}) {
  const store = useStore();
  const [cursor, setCursor] = useState<string>();
  const [preview, setPreview] = useState<ActionCompactionPage>();
  const [applied, setApplied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const run = async (apply: boolean, nextCursor = cursor) => {
    setBusy(true);
    setError(undefined);

    try {
      const result = await compactIntegrationActionHistory(
        store,
        { drive, plugin },
        {
          cursor: nextCursor,
          apply,
          includeCompleted: true,
          includeAutomation: true,
        },
      );
      setCursor(nextCursor);
      setPreview(result);
      setApplied(apply);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <details>
      <summary>Clean up old action details</summary>
      <Column gap='0.5rem'>
        <p>
          Remove old action payloads while keeping IDs, outcomes and recovery
          evidence. Completed results must be at least 30 days old. Automation
          results also require every consuming run to have finished or been
          explicitly abandoned at least 30 days ago. Unfinished runs, untracked
          usage, uncertain or failed writes, and receipts with an unknown
          completion date are kept.
        </p>
        <Button disabled={busy} onClick={() => void run(false, undefined)}>
          Preview cleanup
        </Button>
        <Column>
          {preview && (
            <>
              <p>
                Checked {preview.scanned} old actions; {preview.eligible}{' '}
                eligible for cleanup.
              </p>
              <p>
                Payload reduction: {preview.reclaimableBytes} bytes. Database
                file size may stay the same.
              </p>
              <Column>
                {!applied && preview.eligible > 0 && (
                  <Button disabled={busy} onClick={() => void run(true)}>
                    Archive action details
                  </Button>
                )}
              </Column>
              <Column>
                {applied && <p>Actions archived: {preview.compacted}</p>}
              </Column>
              <Column>
                {preview.nextCursor && (
                  <Button
                    disabled={busy}
                    onClick={() => void run(false, preview.nextCursor!)}
                  >
                    Check next batch
                  </Button>
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
