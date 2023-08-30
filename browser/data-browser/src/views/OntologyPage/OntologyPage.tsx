import React from 'react';
import { ResourcePageProps } from '../ResourcePage';
import { urls, useArray, useCanWrite } from '@tomic/react';
import { OntologySidebar } from './OntologySidebar';
import styled from 'styled-components';
import { ClassCardRead } from './Class/ClassCardRead';
import { PropertyCardRead } from './Property/PropertyCardRead';
import ResourceCard from '../Card/ResourceCard';
import { Button } from '../../components/Button';
import { Column, Row } from '../../components/Row';
import { FaEdit, FaEye } from 'react-icons/fa';
import { OntologyDescription } from './OntologyDescription';
import { ClassCardWrite } from './Class/ClassCardWrite';
import { NewClassButton } from './NewClassButton';
import { toAnchorId } from './toAnchorId';
import { OntologyContextProvider } from './OntologyContext';
import { PropertyCardWrite } from './Property/PropertyCardWrite';

export function OntologyPage({ resource }: ResourcePageProps) {
  const [classes] = useArray(resource, urls.properties.classes);
  const [properties] = useArray(resource, urls.properties.properties);
  const [instances] = useArray(resource, urls.properties.instances);
  const [canWrite] = useCanWrite(resource);

  const [editMode, setEditMode] = React.useState(false);

  return (
    <OntologyContextProvider ontology={resource}>
      <FullPageWrapper edit={editMode}>
        <TitleSlot>
          <Row justify='space-between'>
            <h1>{resource.title}</h1>
            {canWrite &&
              (editMode ? (
                <Button onClick={() => setEditMode(false)}>
                  <FaEye />
                  Read
                </Button>
              ) : (
                <Button onClick={() => setEditMode(true)}>
                  <FaEdit />
                  Edit
                </Button>
              ))}
          </Row>
        </TitleSlot>
        <SidebarSlot>
          <OntologySidebar ontology={resource} />
        </SidebarSlot>
        <ListSlot>
          <Column>
            <OntologyDescription edit={editMode} resource={resource} />
            <h2>Classes</h2>
            <StyledUl>
              {classes.map(c => (
                <li key={c}>
                  {editMode ? (
                    <ClassCardWrite subject={c} />
                  ) : (
                    <ClassCardRead subject={c} />
                  )}
                </li>
              ))}
              {editMode && (
                <li>
                  <NewClassButton resource={resource} />
                </li>
              )}
            </StyledUl>
            <h2>Properties</h2>
            <StyledUl>
              {properties.map(c => (
                <li key={c}>
                  {editMode ? (
                    <PropertyCardWrite subject={c} />
                  ) : (
                    <PropertyCardRead subject={c} />
                  )}
                </li>
              ))}
            </StyledUl>
            <h2>Instances</h2>
            <StyledUl>
              {instances.map(c => (
                <li key={c}>
                  <ResourceCard subject={c} id={toAnchorId(c)} />
                </li>
              ))}
            </StyledUl>
          </Column>
        </ListSlot>
        {!editMode && (
          <GraphSlot>
            <TempGraph>Placeholder</TempGraph>
          </GraphSlot>
        )}
      </FullPageWrapper>
    </OntologyContextProvider>
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

const FullPageWrapper = styled.div<{ edit: boolean }>`
  display: grid;
  grid-template-areas: ${p =>
    p.edit
      ? `'sidebar title title' 'sidebar list list'`
      : `'sidebar title graph' 'sidebar list graph'`};
  grid-template-columns: minmax(auto, 13rem) 3fr 2fr;
  grid-template-rows: 4rem auto;
  width: 100%;
  min-height: ${p => p.theme.heights.fullPage};

  @container (max-width: 950px) {
    grid-template-areas: ${p =>
      p.edit
        ? `'sidebar title' 'sidebar list' 'sidebar list'`
        : `'sidebar title' 'sidebar graph' 'sidebar list'`};

    grid-template-columns: 1fr 5fr;
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
  gap: 2rem;

  & > li {
    margin-left: 0px;
    list-style: none;
  }
`;
