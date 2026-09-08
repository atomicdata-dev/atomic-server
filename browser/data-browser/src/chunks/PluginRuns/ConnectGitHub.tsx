import { BasicSelect } from '@components/forms/BasicSelect';
import { useEffect, useState } from 'react';
import { useStore } from '@tomic/react';
import { Button } from '@components/Button';
import { ExternalLink } from '@components/ExternalLink';
import { Column } from '@components/Row';
import Field from '@components/forms/Field';
import { ErrMessage, Input } from '@components/forms/InputStyles';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import { constructOpenURL } from '@helpers/navigation';
import {
  install,
  compatibleTables,
} from '../../../../../integrations/github-issues/atomic';
import source from '../../../../../integrations/github-issues/plugin.js?raw';

export function ConnectGitHub({ drive }: { drive: string }) {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const [tables, setTables] = useState<
    Awaited<ReturnType<typeof compatibleTables>>
  >([]);
  const [targetTable, setTargetTable] = useState('');
  const [error, setError] = useState<string>();
  useEffect(() => {
    let active = true;
    compatibleTables(store, drive)
      .then(items => {
        if (active) setTables(items);
      })
      .catch(e => {
        if (active) setError(String(e));
      });

    return () => {
      active = false;
    };
  }, [store, drive]);
  const [repository, setRepository] = useState('');
  const tokenUrl = new URL(
    'https://github.com/settings/personal-access-tokens/new',
  );
  tokenUrl.search = new URLSearchParams({
    name: /* @wc-ignore */ 'Atomic issue sync',
    description: /* @wc-ignore */ 'Two-way GitHub issue sync with Atomic',
    expires_in: '30',
    issues: 'write',
  }).toString();
  const repositoryMatch = repository
    .trim()
    .match(/^([a-zA-Z0-9-]+)\/[a-zA-Z0-9_.-]+$/);
  if (repositoryMatch)
    tokenUrl.searchParams.set('target_name', repositoryMatch[1]);
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);

  const connect = async () => {
    if (busy) return;

    if (!repository.trim() || !token.trim()) {
      setError('Enter a repository and token to continue.');

      return;
    }

    setBusy(true);
    setError(undefined);

    try {
      const connection = await install(
        store,
        drive,
        repository.trim(),
        source,
        token.trim(),
        targetTable || undefined,
      );
      setToken('');
      navigate(constructOpenURL(connection.plugin));
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
          Sync issue titles, descriptions and status with a kanban board. Review
          the first import before enabling background sync.
        </p>
        <Field fieldId='github-table' label='Sync into'>
          <BasicSelect
            id='github-table'
            value={targetTable}
            disabled={busy}
            onChange={e => setTargetTable(e.target.value)}
          >
            <option value=''>New issue board</option>
            {tables.map(table => (
              <option key={table.subject} value={table.subject}>
                {table.name}
              </option>
            ))}
          </BasicSelect>
        </Field>
        <p>
          Existing tables appear when they use the shared task schema. GitHub
          supports Todo, Doing and Done; Blocked cards must be resolved before
          syncing. Existing cards are included in the preview.
        </p>
        <Field fieldId='github-repository' label='Repository'>
          <Input
            id='github-repository'
            placeholder='owner/repository'
            value={repository}
            onChange={e => setRepository(e.target.value)}
            disabled={busy}
          />
        </Field>
        <Field fieldId='github-token' label='GitHub token'>
          <ExternalLink to={tokenUrl.toString()}>
            Create GitHub token
          </ExternalLink>
          <p>
            Name, Issues read/write access and a 30-day expiry are prefilled.
            Check the resource owner, choose Only select repositories and select
            your repository. Generate the token, then paste it below.
          </p>
          <Input
            id='github-token'
            type='password'
            autoComplete='off'
            value={token}
            onChange={e => setToken(e.target.value)}
            disabled={busy}
          />
        </Field>
        <p>
          Your token is stored on your AtomicServer. Create the atomic:doing
          label in GitHub to use the Doing column.
        </p>
        <Column aria-live='polite'>
          {error && <ErrMessage role='alert'>{error}</ErrMessage>}
        </Column>
        <Button disabled={busy} type='submit'>
          {busy ? 'Connecting…' : 'Connect GitHub'}
        </Button>
      </Column>
    </form>
  );
}
