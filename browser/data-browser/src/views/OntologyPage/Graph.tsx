import { Resource } from '@tomic/react';
import { lazy, Suspense } from 'react';
import { styled } from 'styled-components';

const OntologyGraph = lazy(
  () => import('../../chunks/GraphViewer/OntologyGraph'),
);

interface GraphProps {
  ontology: Resource;
}

export function Graph({ ontology }: GraphProps): JSX.Element {
  return (
    <GraphWrapper>
      <Suspense fallback='loading...'>
        <OntologyGraph ontology={ontology} />
      </Suspense>
    </GraphWrapper>
  );
}

const GraphWrapper = styled.div`
  position: var(--ontology-graph-position);
  display: grid;
  place-items: center;
  background-color: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  aspect-ratio: var(--ontology-graph-ratio);
  border-radius: ${p => p.theme.radius};
  top: 1rem;
  overflow: hidden;
`;
