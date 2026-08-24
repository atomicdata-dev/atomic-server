import { useStore, type Resource } from '@tomic/react';
import { ContainerFull } from '@components/Containers';
import { LoaderBlock } from '@components/Loader';
import { AppFrame } from './AppFrame';

/**
 * An app opens to its view.
 *
 * By name, not by class: the App resource points at its entry point, so none
 * of the class resolution, view slots or precedence rules the class-to-view
 * path needs apply here.
 */
export function AppPage({
  resource,
}: {
  resource: Resource;
}): React.JSX.Element {
  const store = useStore();
  const drive = store.getDrive();

  if (!drive) {
    return <LoaderBlock />;
  }

  return (
    <ContainerFull>
      <AppFrame app={resource.subject} drive={drive} />
    </ContainerFull>
  );
}
