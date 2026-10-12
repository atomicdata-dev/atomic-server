import { useEffect, useState } from 'react';
import { createRoute, Link } from '@tanstack/react-router';
import { useStore } from '@tomic/react';
import { pathNames, paths } from './paths';
import { appRoute } from './RootRoutes';
import { constructOpenURL } from '../helpers/navigation';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { fetchDriveBreakdown } from '../helpers/storageMapApi';
import { buildStorageTree } from '../helpers/storageMap';
import { StorageView, type Loaded } from '../components/StorageView';

export const StorageRoute = createRoute({
  path: pathNames.storage,
  validateSearch: (search: Record<string, unknown>): { at?: string } => ({
    at: typeof search.at === 'string' ? search.at : undefined,
  }),
  component: () => <StoragePage />,
  getParentRoute: () => appRoute,
});

/** Fetches the drive's per-resource usage and hands it to the size map. */
function StoragePage() {
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
          <Link to={paths.sync}>Back to sync settings</Link>
        </p>
      }
    />
  );
}
