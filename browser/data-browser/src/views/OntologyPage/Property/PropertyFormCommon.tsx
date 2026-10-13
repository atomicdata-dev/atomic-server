import {
  Resource,
  core,
  urls,
  useArray,
  useCanWrite,
  useEffectiveConstraint,
  useProperty,
  useResource,
  useStore,
  useString,
} from '@tomic/react';
import { useCallback, type JSX } from 'react';
import { Column, Row } from '../../../components/Row';
import { SearchBox } from '../../../components/forms/SearchBox';
import { OntologyDescription } from '../OntologyDescription';
import { PropertyDatatypePicker } from '../PropertyDatatypePicker';
import { newClass } from '../ontologyUtils';
import { toAnchorId } from '../../../helpers/toAnchorId';
import { useCurrentSubject } from '../../../helpers/useCurrentSubject';
import InputResourceArray from '../../../components/forms/InputResourceArray';
import { EnumFormPart } from './EnumFormPart';
import { LabelText } from '../LabelText';
import { filterAllowsOnly } from './filterAllowsOnly';
import { isContentAddressed } from '../../../helpers/propertyIdentity';
import { InlineFormattedResourceList } from '../../../components/InlineFormattedResourceList';
import { ResourceInline } from '../../ResourceInline';
import { LinkedClassField } from '../Class/ClassConstraintEditor';

interface PropertyFormCommonProps {
  resource: Resource;
  canEdit: boolean;
  /** The class that uses this property, when opened from one of its lines. */
  classResource?: Resource;
  onClassCreated?: () => void;
}

const datatypesWithExtraControls = new Set([
  urls.datatypes.atomicUrl,
  urls.datatypes.resourceArray,
]);

export function PropertyFormCommon({
  resource,
  canEdit,
  classResource,
  onClassCreated,
}: PropertyFormCommonProps): JSX.Element {
  const store = useStore();

  const [classType, setClassType] = useString(
    resource,
    core.properties.classtype,
    { commit: true },
  );
  const [datatype] = useString(resource, core.properties.datatype);
  const [allowsOnly, setAllowsOnly] = useArray(
    resource,
    core.properties.allowsOnly,
    {
      commit: true,
    },
  );

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

  // A content-addressed property is immutable: the linked class and the
  // options are set per class, in the class card.
  const contentAddressed = isContentAddressed(resource.subject);
  const effective = useEffectiveConstraint(
    classResource ? [classResource.subject] : [],
    resource.subject,
  );
  const canEditClass = useCanWrite(classResource ?? resource);
  const disableExtras = !datatypesWithExtraControls.has(datatype ?? '');
  const showEnumForm =
    !classType && datatypesWithExtraControls.has(datatype ?? '');

  if (contentAddressed) {
    return (
      <Column>
        <OntologyDescription resource={resource} edit />
        <Column fullWidth as='label'>
          <LabelText>Datatype</LabelText>
          <PropertyDatatypePicker disabled={!canEdit} resource={resource} />
        </Column>
        {classResource && datatypesWithExtraControls.has(datatype ?? '') ? (
          <LinkedClassField
            classResource={classResource}
            propertySubject={resource.subject}
            value={effective.class}
            disabled={!canEditClass}
            label='Linked class'
          />
        ) : (
          <p>
            The linked class, options and limits of this property are set per
            class. Open a class that uses it to edit them.
          </p>
        )}
        <LegacyConstraints classType={classType} allowsOnly={allowsOnly} />
      </Column>
    );
  }

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

interface LegacyConstraintsProps {
  classType: string | undefined;
  allowsOnly: string[];
}

/** Read-only view of constraints an older version stored on the Property itself. */
function LegacyConstraints({
  classType,
  allowsOnly,
}: LegacyConstraintsProps): JSX.Element | null {
  if (!classType && allowsOnly.length === 0) {
    return null;
  }

  return (
    <Column>
      <LabelText>Stored on this property (legacy)</LabelText>
      {classType && (
        <div>
          Classtype: <ResourceInline subject={classType} />
        </div>
      )}
      {allowsOnly.length > 0 && (
        <div>
          Allows only: <InlineFormattedResourceList subjects={allowsOnly} />
        </div>
      )}
    </Column>
  );
}
