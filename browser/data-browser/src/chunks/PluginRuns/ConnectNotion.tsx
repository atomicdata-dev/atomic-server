import { useEffect, useRef, useState } from 'react';
import { useStore } from '@tomic/react';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import Field from '@components/forms/Field';
import { ErrMessage, Input } from '@components/forms/InputStyles';
import { BasicSelect } from '@components/forms/BasicSelect';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import { constructOpenURL } from '@helpers/navigation';
import { ConnectNotionManual } from './ConnectNotionManual';
import {
  notionAuth,
  waitForNotion,
  waitForManagedNotion,
  type NotionConnection,
  type NotionDatabase,
} from './notionAuth';

export function ConnectNotion({ drive }: { drive: string }) {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const [connections, setConnections] = useState<NotionConnection[]>([]);
  const [configured, setConfigured] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState('');
  const [databases, setDatabases] = useState<NotionDatabase[]>([]);
  const [database, setDatabase] = useState('');
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState<string | null>(null);
  const [searched, setSearched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState('');
  const [error, setError] = useState('');
  const login = useRef<AbortController | null>(null);
  useEffect(() => {
    let active = true;
    notionAuth<{ configured: boolean; connections: NotionConnection[] }>(
      store,
      'list',
      { drive },
    )
      .then(result => {
        if (active) {
          setConnections(result.connections);
          setConfigured(result.configured);
          setSelected(result.connections[0]?.id ?? '');
          setLoaded(true);
        }
      })
      .catch(e => {
        if (active) {
          setError(String(e));
          setLoaded(true);
        }
      });

    return () => {
      active = false;
      login.current?.abort();
    };
  }, [store, drive]);

  const signIn = async (reconnect = false) => {
    const popup = window.open(
      'about:blank',
      '_blank',
      'popup,width=600,height=760',
    );

    if (!popup) {
      setError('Allow pop-ups for Atomic, then try connecting again.');

      return;
    }

    setBusy(true);
    setProgress('Connecting to Notion…');
    setError('');
    const abort = new AbortController();
    login.current = abort;

    try {
      const start = await notionAuth<{
        url: string;
        state: string;
        mode?: 'managed';
      }>(store, 'start', {
        drive,
        ...(reconnect ? { connection: selected } : {}),
      });

      if (abort.signal.aborted) {
        popup.close();

        return;
      }

      let connection: NotionConnection;

      if (start.mode === 'managed') {
        popup.location.href = start.url;
        connection = await waitForManagedNotion(
          store,
          drive,
          start.state,
          popup,
          abort.signal,
        );
      } else {
        const reply = waitForNotion(
          popup,
          new URL(store.getServerUrl()).origin,
          start.state,
          abort.signal,
        );
        popup.location.href = start.url;
        const result = await reply;
        connection = await notionAuth<NotionConnection>(store, 'finish', {
          drive,
          state: start.state,
          ...result,
        });
      }

      setConnections(previous => [
        ...previous.filter(c => c.id !== connection.id),
        connection,
      ]);
      setSelected(connection.id);
      setDatabases([]);
      setDatabase('');
      setSearched(false);
    } catch (e) {
      popup.close();
      setError(String(e));
    } finally {
      setBusy(false);
      login.current = null;
    }
  };

  const search = async (more = false) => {
    setBusy(true);
    setProgress('Finding databases…');
    setError('');

    try {
      const result = await notionAuth<{
        results: NotionDatabase[];
        cursor: string | null;
      }>(store, 'discover', {
        drive,
        connection: selected,
        query,
        cursor: more ? cursor : null,
      });
      setDatabases(previous =>
        more
          ? [
              ...previous,
              ...result.results.filter(
                item => !previous.some(old => old.id === item.id),
              ),
            ]
          : result.results,
      );
      setCursor(result.cursor);
      setSearched(true);
      if (!more) setDatabase('');
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const preview = async () => {
    setBusy(true);
    setProgress('Setting up your database…');
    setError('');

    try {
      const { installNotion } = await import('./notionInstaller');
      const result = await installNotion(store, drive, database, {
        connection: selected,
      });
      navigate(constructOpenURL(result.table));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Column gap='1rem'>
      <p>
        Choose what to sync from Notion. You’ll review the first sync before any
        changes are applied.
      </p>
      <Column>
        {!loaded && <p>Loading connections…</p>}
        {loaded && !configured && (
          <p>
            Notion sign-in needs to be configured by your server administrator.
            Existing connections can still be used.
          </p>
        )}
      </Column>
      <Column>
        {connections.length > 0 && (
          <>
            <Field label='Notion workspace' fieldId='notion-workspace'>
              <BasicSelect
                id='notion-workspace'
                value={selected}
                disabled={busy}
                onChange={e => {
                  setSelected(e.target.value);
                  setDatabases([]);
                  setDatabase('');
                  setSearched(false);
                  setCursor(null);
                }}
              >
                {connections.map(c => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </BasicSelect>
            </Field>
            <form
              onSubmit={e => {
                e.preventDefault();
                void search();
              }}
            >
              <Column gap='0.75rem'>
                <Field label='Find a database' fieldId='notion-search'>
                  <Input
                    id='notion-search'
                    value={query}
                    disabled={busy}
                    onChange={e => {
                      setQuery(e.target.value);
                      setCursor(null);
                    }}
                    placeholder='Search by name'
                  />
                </Field>
                <Button type='submit' disabled={busy}>
                  Find databases
                </Button>
              </Column>
            </form>
            <Column>
              {databases.length > 0 && (
                <Field label='Database' fieldId='notion-database'>
                  <BasicSelect
                    id='notion-database'
                    value={database}
                    disabled={busy}
                    onChange={e => setDatabase(e.target.value)}
                  >
                    <option value=''>Choose a database</option>
                    {databases.map(d => (
                      <option key={d.id} value={d.id}>
                        {d.icon} {d.name || 'Untitled database'}
                      </option>
                    ))}
                  </BasicSelect>
                </Field>
              )}
            </Column>
            <Column>
              {cursor && (
                <Button subtle disabled={busy} onClick={() => search(true)}>
                  Load more databases
                </Button>
              )}
              {searched && databases.length === 0 && (
                <p>
                  No databases found. Try another name, or reconnect and grant
                  access to the database in Notion.
                </p>
              )}
            </Column>
            <details>
              <summary>Can’t find your database?</summary>
              <p>
                Only databases shared with this connection appear. Reconnect to
                select more pages in Notion, then search again. A database with
                multiple data sources can appear more than once.
              </p>
            </details>
            <Button disabled={busy || !database} onClick={preview}>
              Continue to sync setup
            </Button>
          </>
        )}
      </Column>
      <Row wrapItems>
        <Button
          subtle={connections.length > 0}
          disabled={busy || !configured}
          onClick={() => signIn()}
        >
          {connections.length ? 'Connect another workspace' : 'Connect Notion'}
        </Button>
        {selected && configured && (
          <Button subtle disabled={busy} onClick={() => signIn(true)}>
            Reconnect Notion
          </Button>
        )}
      </Row>
      <Column aria-live='polite'>
        {busy && <p>{progress}</p>}
        {error && <ErrMessage role='alert'>{error}</ErrMessage>}
      </Column>
      <details>
        <summary>Advanced setup with a token</summary>
        <ConnectNotionManual drive={drive} />
      </details>
    </Column>
  );
}
