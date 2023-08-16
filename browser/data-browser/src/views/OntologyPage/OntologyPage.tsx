import React from 'react';
import { ResourcePageProps } from '../ResourcePage';
import { urls, useArray, useString } from '@tomic/react';
import { OntologySidebar } from './OntologySidebar';
import styled from 'styled-components';
import { ClassCardRead } from './ClassCardRead';
import { PropertyCardRead } from './PropertyCardRead';
import ResourceCard from '../Card/ResourceCard';
import { Button } from '../../components/Button';
import { Row } from '../../components/Row';

enum OntologyViewMode {
  Read = 0,
  Write,
}

export function OntologyPage({ resource }: ResourcePageProps) {
  const [description] = useString(resource, urls.properties.description);
  const [classes] = useArray(resource, urls.properties.classes);
  const [properties] = useArray(resource, urls.properties.properties);
  const [instances] = useArray(resource, urls.properties.instances);

  const [viewMode, setViewMode] = React.useState(OntologyViewMode.Read);

  return (
    <FullPageWrapper>
      <TitleSlot>
        <Row justify='space-between'>
          <h1>{resource.title}</h1>
          <Button onClick={() => setViewMode(OntologyViewMode.Write)}>
            Edit
          </Button>
        </Row>
      </TitleSlot>
      <SidebarSlot>
        <OntologySidebar ontology={resource} />
      </SidebarSlot>
      <ListSlot>
        <p>{description}</p>
        <h2>Classes</h2>
        <StyledUl>
          {classes.map(c => (
            <ClassCardRead key={c} subject={c} />
          ))}
        </StyledUl>
        <h2>Properties</h2>
        <StyledUl>
          {properties.map(c => (
            <PropertyCardRead key={c} subject={c} />
          ))}
        </StyledUl>
        <h2>Instances</h2>
        <StyledUl>
          {instances.map(c => (
            <ResourceCard key={c} subject={c} id={`list-item-${c}`} />
          ))}
        </StyledUl>
      </ListSlot>
      <GraphSlot>
        <TempGraph>Placeholder</TempGraph>
      </GraphSlot>
    </FullPageWrapper>
  );
}

const TempGraph = styled.div`
  position: sticky;
  display: grid;
  place-items: center;
  background-color: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  aspect-ratio: 9 / 16;
  border-radius: ${p => p.theme.radius};
  top: 1rem;
  overflow: hidden;
`;

const FullPageWrapper = styled.div`
  display: grid;
  grid-template-areas: 'sidebar title graph' 'sidebar list graph';
  grid-template-columns: 1fr 3fr 2fr;
  grid-template-rows: 4rem auto;
  width: 100%;
  min-height: ${p => p.theme.heights.fullPage};

  @container (max-width: 950px) {
    grid-template-areas: 'sidebar title' 'sidebar graph' 'sidebar list';
    grid-template-columns: 1fr 3fr;
    grid-template-rows: 4rem auto auto;

    ${TempGraph} {
      position: static;
      aspect-ratio: 16/9;
    }
  }
`;

const TitleSlot = styled.div`
  grid-area: title;
  padding: ${p => p.theme.margin}rem;
`;

const SidebarSlot = styled.div`
  grid-area: sidebar;
`;

const ListSlot = styled.div`
  grid-area: list;
  padding: ${p => p.theme.margin}rem;
`;

const GraphSlot = styled.div`
  grid-area: graph;
  padding: ${p => p.theme.margin}rem;
  height: 100%;
`;

const StyledUl = styled.ul`
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;
