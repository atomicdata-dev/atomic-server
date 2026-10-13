import { useCallback, useEffect, useState } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import {
  catalogAppState,
  installCatalogApp,
  readConnectionSubjects,
  readInstalledCatalogApps,
  updateCatalogApp,
  useStore,
  type CatalogApp,
  type InstalledCatalogApp,
} from '@tomic/react';
import { Card } from '@components/Card';
import { Column, Row } from '@components/Row';
import { Button } from '@components/Button';
import { constructOpenURL } from '@helpers/navigation';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import { handOverAppKey } from '@chunks/AppPage/appAgent';
import type { CatalogEntry } from './pluginCatalog';

/** The catalog's app entries this visitor is offered, under the same gates as the rest of the page. */
export function visibleCatalogApps(
  entries: CatalogEntry[],
  options: { query: string; showExperimental: boolean; showApi: boolean },
): CatalogApp[] {
  return entries
    .filter(
      entry =>
        entry.app &&
        entry.enabled &&
        (!entry.experimental || options.showExperimental) &&
        (!entry.requiresApiPlugins || options.showApi),
    )
    .map(entry => entry.app!)
    .filter(app =>
      [app.name, app.description ?? '', app.id]
        .join(' ')
        .toLocaleLowerCase()
        .includes(options.query),
    );
}

/**
 * Drive apps offered by the plugin catalog (`app-module` entries): install
 * one, open it, and move it to the catalog's version when that is newer.
 *
 * Installing downloads the module the entry names, refuses it unless its bytes
 * match the entry's integrity hash, and makes an ordinary app from it — the
 * same app, table, schema and identity the New menu makes. So nothing here is
 * specific to any one app, and an installed app is edited, shared and deleted
 * like any other.
 */
export function CatalogApps({
  entries,
  drive,
  query,
  showExperimental,
  showApi,
}: {
  entries: CatalogEntry[];
  drive: string;
  query: string;
  showExperimental: boolean;
  showApi: boolean;
}): React.JSX.Element | null {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const [installed, setInstalled] = useState<InstalledCatalogApp[]>([]);
  const [busy, setBusy] = useState<string>();

  const refresh = useCallback(
    () =>
      readInstalledCatalogApps(store, drive, property =>
        readConnectionSubjects(store, drive, property),
      ).then(setInstalled),
    [store, drive],
  );

  useEffect(() => {
    refresh().catch(() => setInstalled([]));
  }, [refresh]);

  const apps = visibleCatalogApps(entries, {
    query,
    showExperimental,
    showApi,
  });

  if (apps.length === 0) return null;

  const install = async (app: CatalogApp) => {
    setBusy(app.id);

    try {
      const created = await installCatalogApp(store, { drive, app });

      // As for an app from the New menu: it still works if this fails, but
      // cannot write as itself while nobody is signed in.
      try {
        await handOverAppKey(store, {
          drive,
          app: created.app,
          secret: created.secret,
        });
      } catch (error) {
        store.notifyError(error);
      }

      navigate(constructOpenURL(created.app));
    } catch (error) {
      toast.error(String(error instanceof Error ? error.message : error));
    } finally {
      setBusy(undefined);
    }
  };

  const update = async (app: CatalogApp, subject: string) => {
    setBusy(app.id);

    try {
      await updateCatalogApp(store, { drive, subject, app });
      await refresh();
    } catch (error) {
      toast.error(String(error instanceof Error ? error.message : error));
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <section aria-label='Drive apps'>
      <Column gap='0.75rem'>
        <h2>Drive apps</h2>
        <p>
          Apps that run in their own frame on this drive and keep their rows in
          a table of their own. Each is a published version; installing checks
          its code against the catalog before anything is saved.
        </p>
        <Grid>
          {apps.map(app => {
            const mine = installed.find(i => i.id === app.id);
            const state = catalogAppState(app, mine);

            return (
              <Card key={app.id} data-catalog-app={app.id}>
                <Column gap='1rem'>
                  <Row justify='space-between' center>
                    <Avatar aria-hidden>{app.emoji ?? '🧩'}</Avatar>
                    <Muted>
                      {mine
                        ? `Installed ${mine.version ?? '(unknown version)'}`
                        : `Version ${app.version}`}
                    </Muted>
                  </Row>
                  <div>
                    <h3>{app.name}</h3>
                    {app.description && <Muted>{app.description}</Muted>}
                  </div>
                  <Row wrapItems gap='0.5rem'>
                    {state === 'install' ? (
                      <Button
                        disabled={busy !== undefined}
                        onClick={() => install(app)}
                        aria-label={`Install ${app.name}`}
                      >
                        {busy === app.id ? 'Installing…' : 'Install'}
                      </Button>
                    ) : (
                      <Button
                        subtle
                        onClick={() =>
                          navigate(constructOpenURL(mine!.subject))
                        }
                        aria-label={`Open ${app.name}`}
                      >
                        Open
                      </Button>
                    )}
                    {state === 'update' && (
                      <Button
                        disabled={busy !== undefined}
                        onClick={() => update(app, mine!.subject)}
                      >
                        {busy === app.id
                          ? 'Updating…'
                          : `Update to ${app.version}`}
                      </Button>
                    )}
                  </Row>
                </Column>
              </Card>
            );
          })}
        </Grid>
      </Column>
    </section>
  );
}

const Grid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 19rem), 1fr));
  gap: 1rem;
  align-items: start;
`;
const Avatar = styled.div`
  display: grid;
  place-items: center;
  width: 2.8rem;
  height: 2.8rem;
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg2};
  font-size: 1.3rem;
`;
const Muted = styled.p`
  margin: 0;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.9rem;
`;
