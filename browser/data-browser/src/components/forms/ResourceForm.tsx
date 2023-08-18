import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  useArray,
  useResource,
  useString,
  Resource,
  classes,
  properties,
  urls,
  useDebounce,
  useCanWrite,
  Client,
  useStore,
} from '@tomic/react';
import { styled } from 'styled-components';
import { FaCaretDown, FaCaretRight, FaPlus } from 'react-icons/fa';

import { constructOpenURL } from '../../helpers/navigation';
import { Button } from '../Button';
import ResourceField from './ResourceField';
import { ErrMessage } from './InputStyles';
import { ResourceSelector } from './ResourceSelector';
import Field from './Field';
import UploadForm from './UploadForm';
import { Gutter } from '../Gutter';
import { useSaveResource } from './hooks/useSaveResource';
import { Row } from '../Row';
import { Collapse } from '../Collapse';

export enum ResourceFormVariant {
  Default,
  Dialog,
}

export interface ResourceFormProps {
  /**
   * The type / isA Class of a resource determines the recommended and required
   * form fields.
   */
  classSubject?: string;
  /** Resource that is to be either changed or created */
  resource: Resource;

  variant?: ResourceFormVariant;
}

const nonEssentialProps = [
  properties.isA,
  properties.parent,
  properties.read,
  properties.write,
];

/** Form for editing and creating a Resource */
export function ResourceForm({
  classSubject,
  resource,
  variant,
}: ResourceFormProps): JSX.Element {
  const [isAArray] = useArray(resource, properties.isA);

  if (classSubject === undefined && isAArray?.length > 0) {
    // This is not entirely accurate, as Atomic Data supports having multiple
    // classes for a single resource.
    classSubject = isAArray[0];
  }

  const klass = useResource(classSubject);
  const [requires] = useArray(klass, properties.requires);
  const [recommends] = useArray(klass, properties.recommends);
  const [klassIsa] = useString(klass, properties.isA);
  const [newPropErr, setNewPropErr] = useState<Error | undefined>(undefined);
  const navigate = useNavigate();
  const [newProperty, setNewProperty] = useState<string | undefined>(undefined);
  /** A list of custom properties, set by the User while editing this form */
  const [tempOtherProps, setTempOtherProps] = useState<string[]>([]);
  const [otherProps, setOtherProps] = useState<string[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const store = useStore();
  const wasNew: boolean = resource.new;

  const [save, saving, err] = useSaveResource(resource, () => {
    // We need to read the earlier .new state, because the resource is no
    // longer new after it was saved, during this callback
    wasNew && store.notifyResourceManuallyCreated(resource);
    navigate(constructOpenURL(resource.getSubject()));
  });
  // I'm not entirely sure if debouncing is needed here.
  const debouncedResource = useDebounce(resource, 5000);
  const [_canWrite, canWriteErr] = useCanWrite(debouncedResource);

  /** Builds otherProps */
  useEffect(() => {
    const allProps = Array.from(resource.getPropVals().keys());

    const prps = allProps.filter(prop => {
      // If a property does not exist in other rendered lists, add it to otherprops
      const propIsNotRenderedYet = !(
        requires.includes(prop) ||
        recommends.includes(prop) ||
        tempOtherProps.includes(prop)
      );

      // Non essential properties are not very useful in most cases, only show them if explicitly set
      const isEssential = !nonEssentialProps.includes(prop);

      return propIsNotRenderedYet && isEssential;
    });

    setOtherProps(prps.concat(tempOtherProps));
    // I actually want to run this useEffect every time the requires / recommends
    // array changes, but that leads to a weird loop, so that's what the length is for
  }, [resource, tempOtherProps, requires.length, recommends.length]);

  if (!resource.new && resource.loading) {
    return <>Loading resource...</>;
  }

  if (resource.error) {
    return <ErrMessage>{resource.error.message}</ErrMessage>;
  }

  if (klass.loading) {
    return <>Loading class...</>;
  }

  if (klassIsa && klassIsa !== classes.class) {
    return (
      <ErrMessage>
        {classSubject} is not a Class. Only resources with valid classes can be
        created or edited at this moment.
      </ErrMessage>
    );
  }

  function handleAddProp() {
    setNewPropErr(undefined);

    if (!Client.isValidSubject(newProperty)) {
      setNewPropErr(new Error('Invalid URL'));

      return;
    }

    if (!newProperty) {
      return;
    }

    if (
      tempOtherProps.includes(newProperty) ||
      requires.includes(newProperty) ||
      recommends.includes(newProperty)
    ) {
      setNewPropErr(
        new Error(
          'That property already exists in this resource. It can only be added once.',
        ),
      );
    } else {
      setTempOtherProps(tempOtherProps.concat(newProperty));
    }

    setNewProperty(undefined);
  }

  function handleDelete(propertyURL: string) {
    resource.removePropVal(propertyURL);
    setTempOtherProps(tempOtherProps.filter(prop => prop !== propertyURL));
  }

  return (
    <form about={resource.getSubject()} onSubmit={save}>
      {classSubject && klass.error && (
        <ErrMessage>
          Error in class, so this form could miss properties. You can still edit
          the resource, though. Error message: `{klass.error.message}`
        </ErrMessage>
      )}
      {canWriteErr && <ErrMessage>Cannot save edits: {canWriteErr}</ErrMessage>}
      {requires.map(property => {
        return (
          <ResourceField
            key={property + ' field'}
            propertyURL={property}
            resource={resource}
            required
          />
        );
      })}
      {recommends.map(property => {
        return (
          <ResourceField
            key={property + ' field'}
            propertyURL={property}
            resource={resource}
          />
        );
      })}
      {otherProps.map(property => {
        return (
          <ResourceField
            key={property + ' field'}
            propertyURL={property}
            resource={resource}
            handleDelete={() => handleDelete(property)}
          />
        );
      })}
      <Field
        label='add another property...'
        helper='In Atomic Data, any Resource could have any single Property. Use this field to add new property-value combinations to your resource.'
      >
        <PropertyAdder>
          {/* TODO: When adding a property, clear the form. Make the button optional / remove it. */}
          <Button
            subtle
            disabled={!newProperty}
            onClick={handleAddProp}
            title='Add this property'
          >
            <FaPlus />
          </Button>
          <ResourceSelector
            value={undefined}
            setSubject={(set, _setNewPropErr) => {
              setNewProperty(set);
            }}
            error={newPropErr}
            setError={setNewPropErr}
            classType={urls.classes.property}
          />
        </PropertyAdder>
        {newPropErr && <ErrMessage>{newPropErr.message}</ErrMessage>}
      </Field>
      <UploadForm parentResource={resource} />
      <Gutter />
      <Button
        title={'show / hide advanced form fields'}
        clean
        style={{ display: 'flex', marginBottom: '1rem', alignItems: 'center' }}
        onClick={() => setShowAdvanced(!showAdvanced)}
      >
        <Row as='strong' gap='0.4rem' center>
          {showAdvanced ? <FaCaretDown /> : <FaCaretRight />} Advanced Options
        </Row>
      </Button>
      <Collapse open={showAdvanced}>
        <ResourceField propertyURL={properties.isA} resource={resource} />
        <ResourceField propertyURL={properties.parent} resource={resource} />
        <ResourceField propertyURL={properties.write} resource={resource} />
        <ResourceField propertyURL={properties.read} resource={resource} />
      </Collapse>
      {variant !== ResourceFormVariant.Dialog && (
        <>
          {err && <ErrMessage>{err.message}</ErrMessage>}
          <Button disabled={saving} data-test='save' type='submit'>
            {saving ? 'wait...' : 'save'}
          </Button>
        </>
      )}
    </form>
  );
}

ResourceForm.defaultProps = {
  variant: ResourceFormVariant.Default,
};

const PropertyAdder = styled.div`
  display: flex;
  flex-direction: row;
`;
