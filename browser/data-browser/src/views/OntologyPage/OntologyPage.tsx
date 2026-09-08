import { ResourcePageProps } from '../ResourcePage';
import {
  core,
  useArray,
  useCanWrite,
  useResource,
  type Core,
} from '@tomic/react';
import { OntologySidebar } from './OntologySidebar';
import { styled } from 'styled-components';
import { ClassCardRead } from './Class/ClassCardRead';
import { PropertyCardRead } from './Property/PropertyCardRead';
import { Button } from '../../components/Button';
import { Column, Row } from '../../components/Row';
import { FaPen, FaEye } from 'react-icons/fa6';
import { OntologyDescription } from './OntologyDescription';
import { ClassCardWrite } from './Class/ClassCardWrite';
import { NewClassButton } from './NewClassButton';
import { OntologyContextProvider } from './OntologyContext';
import { PropertyCardWrite } from './Property/PropertyCardWrite';
import { Graph } from './Graph';
import { CreateInstanceButton } from './CreateInstanceButton';
import { useState } from 'react';
import { NewPropertyButton } from './NewPropertyButton';
import { InfoTitle } from './InfoTitle';
import { TargetableResourceCard } from './TargetableCard';

const isEmpty = (arr: Array<unknown>) => arr.length === 0;

export function OntologyPage({ resource }: ResourcePageProps) {
  const classesPropResource = useResource<Core.Property>(
    core.properties.classes,
  );
  const propertiesPropResource = useResource<Core.Property>(
    core.properties.properties,
  );

  const instancesPropResource = useResource<Core.Property>(
    core.properties.instances,
  );

  const [classes] = useArray(resource, core.properties.classes);
  const [properties] = useArray(resource, core.properties.properties);
  const [instances] = useArray(resource, core.properties.instances);
  const canWrite = useCanWrite(resource);

  const [editMode, setEditMode] = useState(
    isEmpty(classes) && isEmpty(properties) && isEmpty(instances),
  );

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
                  <FaPen />
                  Edit
                </Button>
              ))}
          </Row>
        </TitleSlot>
        <SidebarSlot>
          <OntologySidebar ontology={resource} />
        </SidebarSlot>
        <ListSlot>
          <Column style={{ paddingBottom: '3rem' }}>
            <OntologyDescription edit={editMode} resource={resource} />
            <InfoTitle info={classesPropResource.props.description}>
              Classes
            </InfoTitle>
            <StyledUl>
              {editMode && (
                <li>
                  <NewClassButton resource={resource} />
                </li>
              )}
              {classes.map(c => (
                <li key={c}>
                  {editMode ? (
                    <ClassCardWrite subject={c} />
                  ) : (
                    <ClassCardRead subject={c} />
                  )}
                </li>
              ))}
              {!editMode && classes.length === 0 && <span>No classes</span>}
            </StyledUl>
            <InfoTitle info={propertiesPropResource.props.description}>
              Properties
            </InfoTitle>
            <StyledUl>
              {editMode && (
                <li>
                  <NewPropertyButton parent={resource} />
                </li>
              )}
              {properties.map(c => (
                <li key={c}>
                  {editMode ? (
                    <PropertyCardWrite subject={c} />
                  ) : (
                    <PropertyCardRead subject={c} />
                  )}
                </li>
              ))}
              {!editMode && properties.length === 0 && (
                <span>No properties</span>
              )}
            </StyledUl>
            <InfoTitle info={instancesPropResource.props.description}>
              Instances
            </InfoTitle>
            <StyledUl>
              {editMode && <CreateInstanceButton ontology={resource} />}
              {instances.map(c => (
                <li key={c}>
                  <TargetableResourceCard subject={c} />
                </li>
              ))}
              {!editMode && instances.length === 0 && <span>No instances</span>}
            </StyledUl>
          </Column>
        </ListSlot>
        {!editMode && (
          <GraphSlot>
            <Graph ontology={resource} />
          </GraphSlot>
        )}
      </FullPageWrapper>
    </OntologyContextProvider>
  );
}

const SidebarSlot = styled.div`
  grid-area: sidebar;
`;

const ListSlot = styled.div`
  grid-area: list;
  min-width: 0;
  padding: ${p => p.theme.size()};
`;

const FullPageWrapper = styled.div<{ edit: boolean }>`
  --ontology-graph-position: sticky;
  --ontology-graph-ratio: 9 / 16;
  display: grid;
  grid-template-areas: ${p =>
    p.edit
      ? `'title title sidebar' 'list list sidebar'`
      : `'title graph sidebar' 'list graph sidebar'`};
  grid-template-columns: minmax(0, 3fr) minmax(0, 2fr) minmax(auto, 13rem);
  grid-template-rows: 4rem auto;
  width: 100%;
  min-height: ${p => p.theme.heights.fullPage};

  @container (max-width: 950px) {
    grid-template-areas: ${p =>
      p.edit
        ? `'title sidebar' 'list sidebar' 'list sidebar'`
        : `'title sidebar' 'graph sidebar' 'list sidebar'`};

    grid-template-columns: minmax(0, 5fr) minmax(auto, 13rem);
    grid-template-rows: 4rem auto auto;
    --ontology-graph-position: sticky;
    --ontology-graph-ratio: 16/9;
  }

  @container (max-width: 600px) {
    grid-template-areas: ${p =>
      p.edit ? `'title' 'list' 'list'` : `'title' 'graph' 'list'`};
    grid-template-columns: 100cqw;

    ${SidebarSlot} {
      display: none;
    }
  }

  ${ListSlot} {
    width: ${p => (p.edit ? 'min(100%, 80rem)' : 'unset')};
    margin: ${p => (p.edit ? '0 auto' : 'unset')};
  }
`;

const TitleSlot = styled.div`
  grid-area: title;
  padding: ${p => p.theme.size()};
`;

const GraphSlot = styled.div`
  grid-area: graph;
  min-width: 0;
  padding: ${p => p.theme.size()};
  height: 100%;
`;

const StyledUl = styled.ul`
  display: flex;
  flex-direction: column;
  gap: 2rem;

  & > li {
    margin-left: 0px;
    list-style: none;
    margin-bottom: 0;
  }
`;
