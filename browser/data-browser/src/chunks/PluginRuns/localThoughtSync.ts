// @wc-ignore-file
import {
  core,
  dataBrowser,
  applyPlan,
  applyHostFromStore,
  type Store,
} from '@tomic/react';
import type { Config } from '../../../../../integrations/localthought/plugin';
import type { FetchedPlatform } from '../../../../../integrations/localthought/schema';
import { googleCalendarIntegration } from '@localthought/atomic-integrations/ui/GoogleCalendar';
import { browserIntegrations, platformName } from './localThought';
import { ensureLocalInstallationResource } from './installationResources';
import { ensureImportTables } from './localThoughtTables';
import { localImportVerdict } from './localImportVerdict';
import { prepareFromVerdict } from './runScript';

export const REFRESH_INTERVAL = 5 * 60 * 1000;
const prefix = 'localthought-sync-v1:';

export const SYNC_CHANGED = 'localthought-sync-changed';
export interface LocalThoughtInstallation {
  folder: string;
  identity: string;
  origin: string;
  drive: string;
  actor: string;
  platform: string;
  connection: string;
  constants: Record<string, string>;
  selection?: {
    query_overrides: { path: string; values: Record<string, unknown> }[];
  };
  config?: Config;
  syncing?: boolean;
  lastSuccess?: number;
  error?: string;
}
const key = (entry: LocalThoughtInstallation) =>
  prefix + JSON.stringify([entry.drive, entry.actor, entry.folder]);

export function saveInstallation(entry: LocalThoughtInstallation) {
  localStorage.setItem(key(entry), JSON.stringify(entry));
  window.dispatchEvent(new Event(SYNC_CHANGED));
}
export function findInstallation(
  store: Store,
  subject: string,
  parent?: string,
): LocalThoughtInstallation | undefined {
  for (let i = 0; i < localStorage.length; i++) {
    const name = localStorage.key(i)!;
    if (!name.startsWith(prefix)) continue;

    try {
      const entry: LocalThoughtInstallation = JSON.parse(
        localStorage.getItem(name)!,
      );
      if (
        entry.actor !== store.getAgent()?.subject ||
        entry.drive !== store.getDrive()
      )
        continue;
      if (entry.folder === subject || entry.folder === parent) return entry;
    } catch {
      /* An invalid local entry must not prevent other folders opening. */
    }
  }
}

function assertOwner(
  store: Store,
  entry: Pick<LocalThoughtInstallation, 'actor' | 'drive'>,
) {
  if (
    store.getAgent()?.subject !== entry.actor ||
    store.getDrive() !== entry.drive
  )
    throw new Error(
      'Return to the account and drive that installed this integration',
    );
}

export async function installLocalThought(
  store: Store,
  options: Omit<LocalThoughtInstallation, 'folder'>,
) {
  assertOwner(store, options);
  await browserIntegrations(options.origin).validateConnection(
    options.drive,
    options.actor,
    options.connection,
    options.constants,
    options.selection,
  );

  return navigator.locks.request(prefix + options.identity, async () => {
    assertOwner(store, options);
    const folder = await ensureLocalInstallationResource(store, options.drive, {
      parent: options.drive,
      localId: options.identity + ':folder',
      isA: [dataBrowser.classes.folder],
      propVals: { [core.properties.name]: platformName(options.platform) },
    });
    const existing = findInstallation(store, folder.subject);
    const entry = { ...existing, ...options, folder: folder.subject };
    saveInstallation(entry);

    return entry;
  });
}

/** Lock the entire fetch/map/apply cycle, not only credential rotation. */
export async function refreshLocalThought(
  store: Store,
  installation: LocalThoughtInstallation,
): Promise<void> {
  try {
    await navigator.locks.request(
      key(installation),
      { ifAvailable: true },
      async lock => {
        if (!lock) return;
        let entry: LocalThoughtInstallation = JSON.parse(
          localStorage.getItem(key(installation))!,
        );
        if (!entry) return;

        try {
          assertOwner(store, entry);
          entry = { ...entry, syncing: true, error: undefined };
          saveInstallation(entry);
          const response: FetchedPlatform = await browserIntegrations(
            entry.origin,
          ).fetchRecords(
            entry.drive,
            entry.actor,
            entry.connection,
            entry.constants,
            entry.selection,
          );
          if (response.platform !== entry.platform)
            throw new Error('Imported platform did not match this connection');
          const extension = [googleCalendarIntegration].find(
            item => item.id === entry.platform,
          );
          const fetched = extension ? extension.project(response) : response;
          assertOwner(store, entry);
          const folder = await store.getLocalResource(entry.folder);
          if (folder.error || !folder.hasClasses(dataBrowser.classes.folder))
            throw new Error('Integration folder is unavailable');
          const config = await ensureImportTables(
            store,
            entry.drive,
            folder,
            entry.identity + ':folder',
            fetched,
          );
          entry = { ...entry, config };
          saveInstallation(entry);
          assertOwner(store, entry);
          const verdict = await localImportVerdict(store, entry.drive, {
            ...config,
            records: fetched.records,
          });
          const prepared = await prepareFromVerdict(store, verdict, {
            kind: 'manual',
            at: Date.now(),
            subject: entry.folder,
          });
          assertOwner(store, entry);
          if (prepared.plan.blocked)
            throw new Error(
              prepared.plan.problems
                .map(problem => problem.message)
                .join('; ') || 'Sync is blocked by conflicting changes',
            );
          const report = await applyPlan(
            prepared.plan,
            applyHostFromStore(store),
          );
          if (report.failed || report.stoppedEarly)
            throw new Error(
              'Some records could not be synced. Open the folder again to retry.',
            );
          entry = { ...entry, lastSuccess: Date.now() };
        } catch (error) {
          entry = { ...entry, error: String(error) };
        } finally {
          saveInstallation({ ...entry, syncing: false });
        }
      },
    );
  } catch (error) {
    saveInstallation({ ...installation, syncing: false, error: String(error) });
  }
}
