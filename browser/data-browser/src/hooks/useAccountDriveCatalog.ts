import { startVisiblePolling } from '../helpers/visiblePolling';
import { useEffect, useState } from 'react';
import { core, server, useStore } from '@tomic/react';
import { driveDisplayMetadata } from '../helpers/managed/driveDisplayMetadata';
import { hasManagedApi, managedFetch } from '../helpers/managed/api';
import { evaluateIdentityReconciliation } from '../helpers/managed/reconcile';
import { readManagedAccountBinding } from '../helpers/managed/binding';
import { onManagedLogout } from '../helpers/managed/session';
import {
  DriveCatalogSync,
  catalogCacheKey,
  readCatalogCache,
  catalogSubjects,
  type CatalogSnapshot,
} from '../helpers/managed/driveCatalog';

/** Reconcile account membership separately from the user's favorite pointers. */
export function useAccountDriveCatalog(local: string[]) {
  const store = useStore();
  const agent = store.getAgent()?.subject;
  const [snapshot, setSnapshot] = useState<CatalogSnapshot | null>(null);
  const key = JSON.stringify([...new Set(local)].sort());
  useEffect(() => {
    if (!agent || !hasManagedApi()) return;
    let stopped = false;
    let running = false;
    const sync = new DriveCatalogSync({
      identity: async () => {
        const result = await evaluateIdentityReconciliation(agent);

        return !stopped &&
          store.getAgent()?.subject === agent &&
          result.ok &&
          result.managedAccount
          ? { agent, email: result.managedAccount.email }
          : null;
      },
      send: async entries => {
        const response = await managedFetch('/drives/catalog', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(entries),
        });
        if (!response.ok) throw new Error('Could not refresh account drives');

        return response.json();
      },
      changed: next => {
        if (!stopped) {
          setSnapshot(next);

          if (next) {
            try {
              localStorage.setItem(catalogCacheKey(next), JSON.stringify(next));
            } catch {
              /* Memory still retains the list. */
            }
          }
        }
      },
    });

    const binding = readManagedAccountBinding();

    if (binding?.expected_agent_subject === agent) {
      const cached = readCatalogCache(
        { agent, email: binding.owner_email },
        localStorage,
      );

      if (cached) {
        sync.snapshot = cached;
        setSnapshot(cached);
      }
    }

    const refresh = async () => {
      if (running) return;
      running = true;

      try {
        const subjects: string[] = JSON.parse(key);

        // Include newly created owned drives even before they are bookmarked.
        for (const resource of store.resources.values()) {
          if (
            resource.get(core.properties.parent) === agent &&
            resource.hasClasses(server.classes.drive)
          )
            subjects.push(resource.subject);
        }

        const entries = await Promise.all(
          [...new Set(subjects)].map(async subject => {
            const metadata = await driveDisplayMetadata(store, subject);

            return {
              drive_subject: subject,
              drive_name: metadata.name,
              drive_emoji: metadata.emoji,
            };
          }),
        );
        await sync.refresh(entries);
      } catch {
        /* Keep the last successful list; reconnect/focus retries. */
      } finally {
        running = false;
      }
    };

    const stopPolling = startVisiblePolling(refresh, 30000);
    const logout = onManagedLogout(() => {
      if (sync.snapshot) {
        try {
          localStorage.removeItem(catalogCacheKey(sync.snapshot));
        } catch {
          /* The visible list is cleared regardless. */
        }
      }

      sync.reset();
    });

    return () => {
      stopped = true;
      sync.reset();
      logout();
      stopPolling();
    };
  }, [store, agent, key]);
  const current = snapshot?.agent === agent ? snapshot : null;

  return {
    subjects: catalogSubjects(local, current),
    entries: current?.drives ?? [],
    removed: current?.removed ?? [],
  };
}
