import { useEffect, useState } from 'react';
import { useStore, type Resource } from '@tomic/react';
import { findSchema, pluginSchema } from '@tomic/lib';
import { ContainerFull } from '@components/Containers';
import { LoaderBlock } from '@components/Loader';
import { AppFrame } from './AppFrame';

/**
 * An app opens to its view.
 *
 * By name, not by class: the App resource points at its entry point, so none
 * of the class resolution, view slots or precedence rules that the
 * class-to-view path needs apply here.
 */
export function AppPage({
  resource,
}: {
  resource: Resource;
}): React.JSX.Element {
  const store = useStore();
  const drive = store.getDrive();
  const { subject } = resource;
  const [entrypoint, setEntrypoint] = useState<string | null>();

  useEffect(() => {
    if (!drive) return;

    let cancelled = false;

    (async () => {
      const schema = await findSchema(store, drive, pluginSchema());
      const property = schema.properties?.entrypoint;
      // Read through the store rather than the passed resource, so the effect
      // depends on a subject string instead of a proxy whose identity churns.
      const app = await store.getResource(subject);
      const found = property
        ? (app.get(property) as string | undefined)
        : undefined;

      if (!cancelled) setEntrypoint(found ?? null);
    })().catch(() => {
      if (!cancelled) setEntrypoint(null);
    });

    return () => {
      cancelled = true;
    };
  }, [store, drive, subject]);

  if (entrypoint === undefined || !drive) {
    return <LoaderBlock />;
  }

  return (
    <ContainerFull>
      {entrypoint === null ? (
        <p>This app has no entry point, so there is nothing to open.</p>
      ) : (
        <AppFrame app={subject} drive={drive} entrypoint={entrypoint} />
      )}
    </ContainerFull>
  );
}
