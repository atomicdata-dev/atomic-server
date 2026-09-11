import { LocalThoughtCatalog } from '../chunks/PluginRuns/LocalThoughtCatalog';
import { NewAutomation } from '../chunks/PluginRuns/NewAutomation';
import {
  IntegrationDiscovery,
  bundledIntegrations,
} from '../chunks/PluginRuns/IntegrationDiscovery';
import { ConnectedIntegration } from '../chunks/PluginRuns/ConnectedIntegration';
import { createRoute } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { styled } from 'styled-components';
import { FaPlug } from 'react-icons/fa6';
import {
  useStore,
  core,
  findSchema,
  pluginSchema,
  readConnectionSubjects,
  type PluginRelease,
} from '@tomic/react';
import { ResourceInline } from '../views/ResourceInline/ResourceInline';
import toast from 'react-hot-toast';
import { appRoute } from './RootRoutes';
import { pathNames } from './paths';
import { Main } from '@components/Main';
import { ContainerWide } from '@components/Containers';
import { Card } from '@components/Card';
import { Column, Row } from '@components/Row';
import { Button } from '@components/Button';
import { Input } from '@components/forms/InputStyles';
import { useSettings } from '@helpers/AppSettings';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import { constructOpenURL } from '@helpers/navigation';

interface Listing {
  metadata: {
    release: string;
    emoji?: string;
    name: string;
    description: string;
    publisher: string;
    domains: string[];
    standards: string[];
  };
  verification: 'unverified';
}

export const IntegrationStoreRoute = createRoute({
  getParentRoute: () => appRoute,
  path: pathNames.integrations,
  component: IntegrationStore,
  validateSearch: (search: Record<string, unknown>) => ({
    workspace:
      typeof search.workspace === 'string' ? search.workspace : undefined,
  }),
});

function IntegrationStore(): React.JSX.Element {
  const { workspace } = IntegrationStoreRoute.useSearch();
  const store = useStore();
  const { drive } = useSettings();
  const navigate = useNavigateWithTransition();
  const [listings, setListings] = useState<Listing[]>();
  const [installed, setInstalled] = useState<string[]>([]);
  const [automations, setAutomations] = useState<string[]>([]);
  const [error, setError] = useState<string>();
  useEffect(() => {
    let active = true;

    if (!drive) {
      setInstalled([]);

      return;
    }

    void findSchema(store, drive, pluginSchema())
      .then(async schema => {
        const klass = schema.classes?.['plugin-script'];
        const subjects = klass
          ? await readConnectionSubjects(
              store,
              drive,
              core.properties.isA,
              klass,
            )
          : [];
        const resources = await Promise.all(
          subjects.map(subject => store.getResource(subject)),
        );
        const usage = schema.properties?.['automation-integrations'];

        if (active) {
          setInstalled(
            resources
              .filter(resource => !usage || !resource.get(usage))
              .map(resource => resource.subject),
          );
          setAutomations(
            resources
              .filter(resource => usage && resource.get(usage))
              .map(resource => resource.subject),
          );
        }
      })
      .catch(reason => {
        if (active) setError(String(reason));
      });

    return () => {
      active = false;
    };
  }, [store, drive]);
  const [search, setSearch] = useState('');
  const [creating, setCreating] = useState<string>();
  const server = store.getServerUrl();
  useEffect(() => {
    const controller = new AbortController();
    void fetch(`${server}/plugin-catalog`, { signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error(await response.text());
        setListings(await response.json());
      })
      .catch(reason => {
        if (!controller.signal.aborted) setError(String(reason));
      });

    return () => controller.abort();
  }, [server]);

  const createDraft = async (entry: Listing['metadata']) => {
    if (!drive) return;
    setCreating(entry.release);

    try {
      const response = await fetch(
        `${server}/plugin-package/${encodeURIComponent(entry.release)}`,
      );
      if (!response.ok) throw new Error(await response.text());
      const release = (await response.json()) as PluginRelease;
      const { createPlugin } = await import('../chunks/PluginRuns/runScript');
      const subject = await createPlugin(
        store,
        { drive, parent: drive },
        entry.name,
        release.source,
        release.schemas,
      );

      if (entry.emoji) {
        const resource = await store.getResource(subject);
        await resource.set(
          'https://atomicdata.dev/properties/emoji',
          entry.emoji,
        );
        await resource.save();
      }

      navigate(constructOpenURL(subject));
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setCreating(undefined);
    }
  };

  const query = search.trim().toLocaleLowerCase();
  const bundled = bundledIntegrations().filter(entry =>
    `${entry.name} ${entry.description} ${entry.capabilities} ${entry.events} ${entry.keywords}`
      .toLocaleLowerCase()
      .includes(query),
  );
  const visible = listings?.filter(({ metadata: entry }) =>
    [entry.name, entry.description, ...entry.domains, ...entry.standards]
      .join(' ')
      .toLocaleLowerCase()
      .includes(query),
  );

  return (
    <Main>
      <ContainerWide>
        <Column gap='1.5rem'>
          <Header>
            <Icon>
              <FaPlug aria-hidden />
            </Icon>
            <h1>Integrations</h1>
            <p>
              Connect your apps and keep your work in sync. Add automations when
              you need them.
            </p>
          </Header>
          {installed.length > 0 && (
            <section aria-label='Your integrations'>
              <h2>Your connections</h2>
              <Grid>
                {installed.map(subject => (
                  <ConnectedIntegration
                    key={subject}
                    subject={subject}
                    drive={drive!}
                  />
                ))}
              </Grid>
            </section>
          )}
          {drive && (
            <section aria-label='Your automations'>
              <Row center justify='space-between'>
                <h2>Your automations</h2>
                <NewAutomation drive={drive} connections={installed} />
              </Row>
              {automations.length === 0 && <AutomationEmptyState />}
              <Grid>
                {automations.map(subject => (
                  <Card key={subject}>
                    <ResourceInline subject={subject} />
                  </Card>
                ))}
              </Grid>
            </section>
          )}
          <h2>Discover integrations</h2>
          <Input
            aria-label='Search integrations'
            placeholder='Search integrations, domains or standards'
            value={search}
            onChange={event => setSearch(event.target.value)}
          />
          {error && <Card role='alert'>{error}</Card>}
          {!listings && !error && <p>Loading integrations…</p>}
          <Grid>
            <LocalThoughtCatalog drive={drive} search={search} />
            {bundled.map(entry => (
              <IntegrationDiscovery
                key={entry.id}
                entry={entry}
                workspace={workspace}
                drive={drive}
              />
            ))}
          </Grid>
          <Column gap='0.75rem'>
            {visible && visible.length > 0 && (
              <>
                <h2>Community plugins</h2>
                <p>
                  Published code you can adapt. Creating a draft does not
                  connect an app or enable sync.
                </p>
              </>
            )}
          </Column>
          <Grid>
            {visible?.map(({ metadata: entry }) => (
              <Card
                key={`${entry.release}:${entry.publisher}`}
                data-release={entry.release}
              >
                <Column gap='1rem'>
                  <Row justify='space-between' center>
                    <Avatar aria-hidden>{entry.emoji || <FaPlug />}</Avatar>
                    <Badge>Unverified</Badge>
                  </Row>
                  <div>
                    <h2>{entry.name}</h2>
                    <Description>{entry.description}</Description>
                  </div>
                  <Row wrapItems gap='0.4rem'>
                    {entry.domains.map(domain => (
                      <Tag key={domain}>{domain}</Tag>
                    ))}
                  </Row>
                  {entry.standards.length > 0 && (
                    <details>
                      <summary>Linked standards</summary>
                      <ul>
                        {entry.standards
                          .filter(standard => /^https?:\/\//i.test(standard))
                          .map(standard => (
                            <li key={standard}>
                              <a
                                href={standard}
                                target='_blank'
                                rel='noreferrer'
                              >
                                {standard}
                              </a>
                            </li>
                          ))}
                      </ul>
                    </details>
                  )}
                  <details>
                    <summary>Publisher and release</summary>
                    <Identity>
                      {entry.publisher}
                      <br />
                      {entry.release}
                    </Identity>
                  </details>
                  <Button
                    disabled={!drive || creating !== undefined}
                    onClick={() => createDraft(entry)}
                  >
                    {creating === entry.release
                      ? 'Creating draft…'
                      : 'Create draft'}
                  </Button>
                </Column>
              </Card>
            ))}
          </Grid>
        </Column>
      </ContainerWide>
    </Main>
  );
}

const Header = styled.header`
  padding: 2rem 0 1rem;
  max-width: 42rem;
  h1 {
    margin: 0.8rem 0;
  }
  p {
    color: ${p => p.theme.colors.textLight};
  }
`;
const Icon = styled.div`
  color: ${p => p.theme.colors.main};
  font-size: 2rem;
`;
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
  font-weight: bold;
`;
const Badge = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.8rem;
`;
const Tag = styled.span`
  border: 1px solid ${p => p.theme.colors.bg2};
  padding: 0.2rem 0.5rem;
  border-radius: ${p => p.theme.radius};
  font-size: 0.85rem;
`;
const Description = styled.p`
  color: ${p => p.theme.colors.textLight};
  line-height: 1.5;
`;
const Identity = styled.p`
  overflow-wrap: anywhere;
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
`;

function AutomationEmptyState() {
  return (
    <p>
      No automations yet. Create one to respond to events from your connected
      apps.
    </p>
  );
}
