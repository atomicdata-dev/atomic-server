import { core } from '@tomic/react';
import AllProps from '../components/AllProps';
import { ClassDetail } from '../components/ClassDetail';
import { ContainerNarrow } from '../components/Containers';
import { ValueForm } from '../components/forms/ValueForm';
import { NewInstanceButton } from '../components/NewInstanceButton';
import { Title } from '../components/Title';
import { Column, Row } from '../components/Row';
import { ResourcePageProps } from './ResourcePage';
import { defaultHiddenProps } from './ResourcePageDefault';

/**
 * Full page Class resoure that features a New instance button, and a Typescript
 * definition export.
 */
export function ClassPage({ resource }: ResourcePageProps) {
  return (
    <ContainerNarrow about={resource.subject}>
      <Title resource={resource} />
      <ClassDetail resource={resource} />
      <ValueForm
        resource={resource}
        propertyURL={core.properties.description}
      />
      <Column>
        <AllProps
          resource={resource}
          except={defaultHiddenProps}
          editable
          columns
        />
        <Row>
          <NewInstanceButton icon={true} klass={resource.subject} />
        </Row>
      </Column>
    </ContainerNarrow>
  );
}
