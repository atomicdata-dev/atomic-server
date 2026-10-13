import { useEffect, useState, type JSX } from 'react';
import { useArray, useCanWrite, dataBrowser, useStore } from '@tomic/react';
import { styled } from 'styled-components';

import { ElementShow } from './Element';
import { ResourcePageProps } from './ResourcePage';
import { Column, Row } from '../components/Row';
import { Spinner } from '../components/Spinner';
import { upgradeDocument } from './Document/upgradeDocument';
import {
  PAGE_TITLE_TRANSITION_TAG,
  transitionName,
} from '../helpers/transitionName';
import { ViewTransitionProps } from '../helpers/ViewTransitionProps';

/** Full-page view for a V1 document. Writable ones migrate to V2 silently. */
export function DocumentPage({ resource }: ResourcePageProps): JSX.Element {
  const store = useStore();
  const canWrite = useCanWrite(resource);
  const [elements] = useArray(resource, dataBrowser.properties.elements);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!canWrite || failed) {
      return;
    }

    let cancelled = false;

    upgradeDocument(resource, store).catch(error => {
      console.error('[upgradeDocument] V1 migration failed:', error);

      if (!cancelled) {
        setFailed(true);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [canWrite, failed, resource, store]);

  return (
    <FullPageWrapper>
      <DocumentContainer>
        <Column fullHeight>
          <Row>
            <DocumentTitle subject={resource.subject}>
              {resource.title}
            </DocumentTitle>
          </Row>
          {canWrite && !failed ? (
            <Spinner centered size='2.5rem' />
          ) : (
            <div>
              {elements.map(subject => (
                <ElementShow subject={subject} key={subject} />
              ))}
            </div>
          )}
        </Column>
      </DocumentContainer>
    </FullPageWrapper>
  );
}

const DocumentTitle = styled.h1<ViewTransitionProps>`
  width: fit-content;
  max-width: 100%;
  ${p => transitionName(PAGE_TITLE_TRANSITION_TAG, p.subject)};
`;

const DocumentContainer = styled.div`
  width: min(100%, ${p => p.theme.containerWidth}rem);
  margin: auto;
  display: flex;
  flex: 1;
  flex-direction: column;
  padding: 2rem;
  @media (max-width: ${props => props.theme.containerWidth}rem) {
    padding: ${p => p.theme.size()};
  }
`;

const FullPageWrapper = styled.div`
  background-color: ${p => p.theme.colors.bg};
  display: flex;
  flex: 1;
  flex-direction: column;
  min-height: ${p => p.theme.heights.fullPage};
  box-sizing: border-box;
`;

export default DocumentPage;
