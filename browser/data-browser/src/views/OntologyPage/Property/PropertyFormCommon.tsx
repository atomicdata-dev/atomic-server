import {
  Resource,
  urls,
  useProperty,
  useResource,
  useStore,
  useString,
} from '@tomic/react';
import React, { useCallback } from 'react';
import { Column, Row } from '../../../components/Row';
import { SearchBox } from '../../../components/forms/SearchBox';
import { OntologyDescription } from '../OntologyDescription';
import { PropertyDatatypePicker } from '../PropertyDatatypePicker';
import styled from 'styled-components';
import { newClass } from '../newClass';
import { toAnchorId } from '../toAnchorId';
import { useCurrentSubject } from '../../../helpers/useCurrentSubject';
import InputSwitcher from '../../../components/forms/InputSwitcher';

interface PropertyFormCommonProps {
  resource: Resource;
  canEdit: boolean;
  onClassCreated?: () => void;
}

const datatypesWithExtraControls = new Set([
  urls.datatypes.atomicUrl,
  urls.datatypes.resourceArray,
]);

export function PropertyFormCommon({
  resource,
  canEdit,
  onClassCreated,
}: PropertyFormCommonProps): JSX.Element {
  const store = useStore();
  const [classType, setClassType] = useString(
    resource,
    urls.properties.classType,
    { commit: true },
  );
  const [datatype] = useString(resource, urls.properties.datatype);
  const [ontologySubject] = useCurrentSubject();
  const ontologyResource = useResource(ontologySubject);
  const allowsOnly = useProperty(urls.properties.allowsOnly);

  const handleCreateClass = useCallback(
    async (shortname: string) => {
      const createdSubject = await newClass(shortname, ontologyResource, store);
      await setClassType(createdSubject);
      onClassCreated?.();

      requestAnimationFrame(() => {
        document
          .getElementById(toAnchorId(createdSubject))
          ?.scrollIntoView({ behavior: 'smooth' });
      });
    },
    [ontologyResource, store, onClassCreated],
  );

  const disableExtras = !datatypesWithExtraControls.has(datatype ?? '');

  return (
    <Column>
      <OntologyDescription resource={resource} edit />
      <Row>
        <Column fullWidth as='label'>
          <LabelText>Datatype</LabelText>
          <PropertyDatatypePicker disabled={!canEdit} resource={resource} />
        </Column>
        <Column fullWidth as='label'>
          <LabelText>Classtype</LabelText>
          <SearchBox
            disabled={!canEdit || disableExtras}
            value={classType}
            onChange={setClassType}
            isA={urls.classes.class}
            onCreateItem={handleCreateClass}
          />
        </Column>
      </Row>
      <Column>
        <LabelText>Allows Only</LabelText>
        <InputSwitcher
          resource={resource}
          property={allowsOnly}
          disabled={disableExtras}
        />
      </Column>
    </Column>
  );
}

const LabelText = styled.span`
  font-weight: bold;
  color: ${p => p.theme.colors.textLight};
`;
