import { Resource } from '@tomic/react';
import { lazy, Suspense, type JSX } from 'react';
import { styled } from 'styled-components';
import { Spinner } from '../../components/Spinner';

const OntologyGraph = lazy(
  () => import('../../chunks/GraphViewer/OntologyGraph'),
);

interface GraphProps {
  ontology: Resource;
}

export function Graph({ ontology }: GraphProps): JSX.Element {
  return (
    <GraphWrapper>
      <Suspense fallback={<Spinner centered />}>
        <OntologyGraph ontology={ontology} />
      </Suspense>
    </GraphWrapper>
  );
}

const GraphWrapper = styled.div`
  position: var(--ontology-graph-position);
  display: grid;
  place-items: stretch;
  min-width: 0;
  background-color: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  aspect-ratio: var(--ontology-graph-ratio);
  border-radius: ${p => p.theme.radius};
  top: 1rem;
  overflow: hidden;
`;
