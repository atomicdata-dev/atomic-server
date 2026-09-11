import {
  core,
  ensureSchema,
  findSchema,
  server,
  useCurrentAgent,
  useResource,
  useStore,
} from '@tomic/react';
import { useEffect, useState } from 'react';
import { usePrivateDrive } from './usePrivateDrive';
import {
  integrationVisibility,
  integrationVisibilitySchema,
  type IntegrationVisibilityKey,
} from '@helpers/integrationVisibility';

export function useIntegrationVisibility() {
  const store = useStore();
  const [agent] = useCurrentAgent();
  const actor = agent?.subject;
  const { privateDrive, loading } = usePrivateDrive();
  const resource = useResource(loading ? undefined : privateDrive);
  const ontologySubject = resource.get(server.properties.defaultOntology);
  const ontology = useResource(
    typeof ontologySubject === 'string' ? ontologySubject : undefined,
  );
  const ontologyProperties = JSON.stringify(
    ontology.get(core.properties.properties),
  );
  const [resolved, setResolved] = useState<{
    actor: string;
    drive: string;
    properties: Record<string, string>;
  }>();
  const [saving, setSaving] = useState(false);
  const [pending, setPending] = useState<{
    actor: string;
    drive: string;
    key: IntegrationVisibilityKey;
    value: boolean;
  }>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    let active = true;
    setResolved(undefined);
    setError(undefined);
    if (!privateDrive || loading || !actor) return;
    void findSchema(store, privateDrive, integrationVisibilitySchema())
      .then(schema => {
        if (active)
          setResolved({
            actor,
            drive: privateDrive,
            properties: schema.properties ?? {},
          });
      })
      .catch(reason => {
        if (active) setError(String(reason));
      });

    return () => {
      active = false;
    };
  }, [
    store,
    actor,
    privateDrive,
    loading,
    ontologySubject,
    ontologyProperties,
  ]);

  const ready =
    !loading &&
    !!privateDrive &&
    resolved?.drive === privateDrive &&
    resolved?.actor === actor &&
    !resource.loading &&
    !resource.error;
  const visibility = integrationVisibility(
    resource,
    ready ? resolved.properties : {},
  );

  const setVisibility = async (
    key: IntegrationVisibilityKey,
    value: boolean,
  ) => {
    if (!ready || saving || !actor) return;
    setPending({ actor, drive: privateDrive, key, value });
    setSaving(true);
    setError(undefined);

    try {
      const schema = await ensureSchema(
        store,
        privateDrive,
        integrationVisibilitySchema(),
      );
      const drive = await store.getResource(privateDrive);
      if (store.getAgent()?.subject !== actor) return;
      await drive.set(schema.properties[key], value);
      await drive.save();
      setResolved({
        actor,
        drive: privateDrive,
        properties: schema.properties,
      });
    } catch (reason) {
      setError(String(reason));
    } finally {
      setPending(undefined);
      setSaving(false);
    }
  };

  const optimistic =
    pending?.actor === actor && pending?.drive === privateDrive
      ? pending
      : undefined;

  return {
    showApiPlugins:
      optimistic?.key === 'show-api-plugins'
        ? optimistic.value
        : visibility.showApiPlugins,
    showExperimentalPlugins:
      optimistic?.key === 'show-experimental-plugins'
        ? optimistic.value
        : visibility.showExperimentalPlugins,
    ready,
    saving,
    error,
    setVisibility,
  };
}
