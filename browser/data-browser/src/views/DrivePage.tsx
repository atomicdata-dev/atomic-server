import {
  useArray,
  Datatype,
  dataBrowser,
  core,
  server,
  useProperty,
  useCanWrite,
} from '@tomic/react';
import { ContainerNarrow } from '../components/Containers';
import { Card, CardInsideFull, CardRow } from '../components/Card';
import { ResourceInline } from './ResourceInline';
import { ValueForm } from '../components/forms/ValueForm';
import { Button } from '../components/Button';
import { useSettings } from '../helpers/AppSettings';
import { AtomicLink } from '../components/AtomicLink';
import { FaPlus } from 'react-icons/fa';
import { paths } from '../routes/paths';
import { ResourcePageProps } from './ResourcePage';
import { EditableTitle } from '../components/EditableTitle';
import { Column, Row } from '../components/Row';
import { styled } from 'styled-components';
import InputSwitcher from '../components/forms/InputSwitcher';

/** A View for Drives, which function similar to a homepage or dashboard. */
function DrivePage({ resource }: ResourcePageProps): JSX.Element {
  const [subResources] = useArray(
    resource,
    dataBrowser.properties.subResources,
  );
  const { drive: baseURL, setDrive: setBaseURL } = useSettings();

  const defaultOntologyProp = useProperty(server.properties.defaultOntology);
  const [canEdit] = useCanWrite(resource);

  if (!baseURL) {
    setBaseURL(resource.subject);
  }

  return (
    <ContainerNarrow>
      <Column>
        <Row>
          <EditableTitle resource={resource} />
          {baseURL !== resource.subject && (
            <Button onClick={() => setBaseURL(resource.subject)}>
              Set as current drive
            </Button>
          )}
        </Row>
        <ValueForm
          resource={resource}
          propertyURL={core.properties.description}
          datatype={Datatype.MARKDOWN}
        />
        <div>
          <Heading>Default Ontology</Heading>
          <InputSwitcher
            resource={resource}
            property={defaultOntologyProp}
            disabled={!canEdit}
          />
        </div>
        <Card>
          <Heading>Resources:</Heading>
          <CardInsideFull>
            {subResources.map(child => (
              <CardRow key={child}>
                <ResourceInline subject={child} />
              </CardRow>
            ))}
            <CardRow>
              <AtomicLink path={paths.new}>
                <FaPlus /> Create new resource
              </AtomicLink>
            </CardRow>
          </CardInsideFull>
        </Card>
        {baseURL.startsWith('http://localhost') && (
          <p>
            You are running Atomic-Server on `localhost`, which means that it
            will not be available from any other machine than your current local
            device. If you want your Atomic-Server to be available from the web,
            you should set this up at a Domain on a server.
          </p>
        )}
      </Column>
    </ContainerNarrow>
  );
}

export default DrivePage;

const Heading = styled.h2`
  font-size: 1.3rem;
`;
