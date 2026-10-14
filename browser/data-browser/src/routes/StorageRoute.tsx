import { lazy, Suspense, useEffect, useState } from 'react';
import { createRoute, Link } from '@tanstack/react-router';
import { useStore } from '@tomic/react';
import { pathNames, paths } from './paths';
import { appRoute } from './RootRoutes';
import { constructOpenURL } from '../helpers/navigation';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { fetchDriveBreakdown } from '../helpers/storageMapApi';
import { buildStorageTree } from '../helpers/storageMap';
import { StorageView, type Loaded } from '../components/StorageView';

const VaultAccountStorage = lazy(() =>
  import('../components/Vault/VaultAccountStorage').then(module => ({
    default: module.VaultAccountStorage,
  })),
);

export const StorageRoute = createRoute({
  path: pathNames.storage,
  validateSearch: (
    search: Record<string, unknown>,
  ): { at?: string; view?: 'vault' } => ({
    at: typeof search.at === 'string' ? search.at : undefined,
    view: search.view === 'vault' ? 'vault' : undefined,
  }),
  component: () => <StoragePage />,
  getParentRoute: () => appRoute,
});

/** Fetches the drive's per-resource usage and hands it to the size map. */
function StoragePage() {
  const { view } = StorageRoute.useSearch();
  if (view === 'vault')
    return (
      <Suspense fallback={<p>Loading storage…</p>}>
        <VaultAccountStorage />
      </Suspense>
    );

  return <ServerStoragePage />;
}

function ServerStoragePage() {
  const store = useStore();
  const { at } = StorageRoute.useSearch();
  const navigate = useNavigateWithTransition();
  const [loaded, setLoaded] = useState<Loaded>({ state: 'loading' });

  useEffect(() => {
    const { drive, serverUrl } = store.getSyncStatus();
    const agent = store.getAgent();
    let cancelled = false;

    if (!drive || !agent) {
      setLoaded({ state: 'failed' });

      return;
    }

    fetchDriveBreakdown(serverUrl, drive, agent).then(rows => {
      if (cancelled) return;

      setLoaded(
        rows
          ? { state: 'ready', root: buildStorageTree(rows, drive) }
          : { state: 'failed' },
      );
    });

    return () => {
      cancelled = true;
    };
  }, [store]);

  return (
    <StorageView
      loaded={loaded}
      startAt={at}
      onOpen={subject => navigate(constructOpenURL(subject))}
      backTo={
        <p>
          <Link to={paths.sync}>Back to sync settings</Link> ·{' '}
          <Link to={paths.storage} search={{ view: 'vault' }}>
            All workspace backups
          </Link>
        </p>
      }
    />
  );
}
