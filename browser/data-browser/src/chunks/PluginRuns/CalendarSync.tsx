import { useState } from 'react';
import { useStore, type JSONValue } from '@tomic/react';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import { ErrMessage } from '@components/forms/InputStyles';
import { browserIntegrations } from './localThought';
import { localImportRows } from './localImportVerdict';
import type { Config } from '../../../../../integrations/localthought/plugin';
import {
  applyCalendarEdit,
  previewCalendarEdits,
  type CalendarEdit,
} from '../../../../../integrations/localthought/calendar-sync';

export function CalendarSync({
  drive,
  connection,
  config,
  disabled,
}: {
  drive: string;
  connection: string;
  config: Config;
  disabled: boolean;
}) {
  const store = useStore();
  const [edits, setEdits] = useState<CalendarEdit[]>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const request = (
    path: string,
    init?: { method?: string; body?: string; ifMatch?: string },
  ) =>
    browserIntegrations().request(
      drive,
      store.getAgent()?.subject ?? '',
      connection,
      'google-calendar',
      path,
      init,
    );
  const preview = async () => {
    setBusy(true);
    setError('');
    setDone(false);
    setEdits(undefined);
    try {
      setEdits(
        await previewCalendarEdits(
          await localImportRows(store, drive, config),
          config,
          request,
        ),
      );
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };
  const apply = async () => {
    if (!edits || busy) return;
    setBusy(true);
    setError('');
    try {
      for (const edit of edits) {
        const resource = await store.getResource(edit.subject);
        await applyCalendarEdit(
          edit,
          async () => resource.getPropVals(),
          request,
          async values => {
            for (const [property, value] of Object.entries(values))
              await resource.set(property, value as JSONValue);
            await resource.save();
          },
        );
      }
      setDone(true);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
      setEdits(undefined);
    }
  };
  return (
    <Column gap='0.75rem'>
      <p>
        Send edits to imported events back to Google: Name or Summary,
        Description, Location, Start and End. Edit Start and End together to
        change duration or all-day dates. Calendar day and all-day display
        columns are derived on import. New events, deletion, recurrence rules,
        guests and RSVP stay in Google. Reconnect with Calendar write access
        before your first sync.
      </p>
      <Button disabled={disabled || busy} onClick={preview}>
        {busy ? 'Syncing…' : 'Preview edits for Google'}
      </Button>
      {edits && (
        <>
          {!edits.length && <p>No supported local edits to send.</p>}
          {edits.map(edit => (
            <div key={edit.subject}>
              <strong>{edit.name}</strong>
              <pre>{JSON.stringify(edit.patch, null, 2)}</pre>
            </div>
          ))}
          {!!edits.length && (
            <>
              <p>
                Applying these edits updates Google Calendar and notifies event
                guests.
              </p>
              <Button disabled={disabled || busy} onClick={apply}>
                Apply edits to Google
              </Button>
            </>
          )}
        </>
      )}
      {done && (
        <p>
          Edits synced. Fetch and preview to receive the latest Google changes.
        </p>
      )}
      {error && <ErrMessage role='alert'>{error}</ErrMessage>}
    </Column>
  );
}
