import { styled } from 'styled-components';
import { useStore, type Resource } from '@tomic/react';
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
    <PageWrapper>
      <AppFrame app={resource.subject} drive={drive} />
    </PageWrapper>
  );
}

/**
 * An app gets the whole page.
 *
 * Not ContainerFull: its bottom padding exists so a scrolling column of
 * resources clears the navigation bar, but a frame cannot grow into padding —
 * it would just leave a strip of empty page under an app that had already run
 * out of room.
 */
const PageWrapper = styled.div`
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  padding: ${p => p.theme.size()};
`;
