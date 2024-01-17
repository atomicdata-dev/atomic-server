import {
  Resource,
  core,
  urls,
  useArray,
  useProperty,
  useResource,
  useStore,
  useString,
} from '@tomic/react';
import { useCallback } from 'react';
import { Column, Row } from '../../../components/Row';
import { SearchBox } from '../../../components/forms/SearchBox';
import { OntologyDescription } from '../OntologyDescription';
import { PropertyDatatypePicker } from '../PropertyDatatypePicker';
import { newClass } from '../newClass';
import { toAnchorId } from '../toAnchorId';
import { useCurrentSubject } from '../../../helpers/useCurrentSubject';
import InputResourceArray from '../../../components/forms/InputResourceArray';
import { EnumFormPart } from './EnumFormPart';
import { LabelText } from '../LabelText';
import { filterAllowsOnly } from './filterAllowsOnly';

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
    core.properties.classtype,
    { commit: true },
  );
  const [datatype] = useString(resource, core.properties.datatype);
  const [_, setAllowsOnly] = useArray(resource, core.properties.allowsOnly, {
    commit: true,
  });

  const [ontologySubject] = useCurrentSubject();
  const ontologyResource = useResource(ontologySubject);
  const allowsOnlyProp = useProperty(core.properties.allowsOnly);

  const createClass = useCallback(
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

  const filterNotAllowedTypesFromAllowsOnly = useCallback(
    async (newType: string | undefined) => {
      if (newType === undefined) {
        return;
      }

      const filtered = await filterAllowsOnly(resource, newType, store);
      setAllowsOnly(filtered);
    },
    [store, resource, setAllowsOnly],
  );

  const handleClassTypeChange = useCallback(
    (newType: string | undefined) => {
      setClassType(newType);
      filterNotAllowedTypesFromAllowsOnly(newType);
    },
    [setClassType, filterNotAllowedTypesFromAllowsOnly],
  );

  const disableExtras = !datatypesWithExtraControls.has(datatype ?? '');
  const showEnumForm =
    !classType && datatypesWithExtraControls.has(datatype ?? '');

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
            onChange={handleClassTypeChange}
            isA={core.classes.class}
            onCreateItem={createClass}
          />
        </Column>
      </Row>
      {showEnumForm && (
        <EnumFormPart resource={resource} ontology={ontologyResource} />
      )}
      {classType && (
        <Column>
          <LabelText>Allows Only</LabelText>
          <InputResourceArray
            resource={resource}
            property={allowsOnlyProp}
            isA={classType}
          />
        </Column>
      )}
    </Column>
  );
}
