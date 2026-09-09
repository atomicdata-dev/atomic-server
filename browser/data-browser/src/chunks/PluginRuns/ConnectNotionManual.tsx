import { useState } from 'react';
import { useStore } from '@tomic/react';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import Field from '@components/forms/Field';
import { ErrMessage, Input } from '@components/forms/InputStyles';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import { constructOpenURL } from '@helpers/navigation';

export function ConnectNotionManual({ drive }: { drive: string }) {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const [dataSource, setDataSource] = useState('');
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const connect = async () => {
    if (busy) return;

    if (!dataSource.trim() || !token.trim()) {
      setError('Enter a data source ID and connection token to continue.');

      return;
    }

    setBusy(true);
    setError(undefined);

    try {
      const { installNotion } = await import('./notionInstaller');
      const connection = await installNotion(
        store,
        drive,
        dataSource.trim(),
        token.trim(),
      );
      setToken('');
      navigate(constructOpenURL(connection.table));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      onSubmit={event => {
        event.preventDefault();
        void connect();
      }}
    >
      <Column gap='0.75rem'>
        <p>
          Connect a Notion database, then review what will sync before making
          changes.
        </p>
        <Field fieldId='notion-data-source' label='Data source ID'>
          <Input
            id='notion-data-source'
            value={dataSource}
            onChange={e => setDataSource(e.target.value)}
            disabled={busy}
          />
        </Field>
        <p>
          Use the data source UUID from Notion, not a database URL. Share its
          database with your Notion connection first.
        </p>
        <Field fieldId='notion-token' label='Notion connection token'>
          <Input
            id='notion-token'
            type='password'
            autoComplete='off'
            value={token}
            onChange={e => setToken(e.target.value)}
            disabled={busy}
          />
        </Field>
        <p>
          The token is stored on your AtomicServer. Formatted text, relations,
          formulas and filtered views need additional mappings. Compatibility
          notes appear on the connection before you approve any sync.
        </p>
        <Column aria-live='polite'>
          {error && <ErrMessage role='alert'>{error}</ErrMessage>}
        </Column>
        <Button disabled={busy} type='submit'>
          {busy ? 'Connecting…' : 'Connect Notion'}
        </Button>
      </Column>
    </form>
  );
}
