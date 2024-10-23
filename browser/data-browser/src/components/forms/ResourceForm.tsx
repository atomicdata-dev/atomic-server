import { useCallback, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  useArray,
  useResource,
  Resource,
  useCanWrite,
  Client,
  useStore,
  core,
  commits,
  dataBrowser,
} from '@tomic/react';
import { FaCaretDown, FaCaretRight } from 'react-icons/fa';

import { constructOpenURL } from '../../helpers/navigation';
import { Button } from '../Button';
import ResourceField from './ResourceField';
import { ErrMessage, InlineErrMessage } from './InputStyles';
import { ResourceSelector } from './ResourceSelector';
import Field from './Field';
import { Gutter } from '../Gutter';
import { useSaveResource } from './hooks/useSaveResource';
import { Column, Row } from '../Row';
import { Collapse } from '../Collapse';
import styled from 'styled-components';
import { FaFloppyDisk } from 'react-icons/fa6';
import { FormValidationContextProvider } from './formValidation/FormValidationContextProvider';
import { useOnline } from '../../hooks/useOnline';
import {
  RESOURCE_FORM_CONTEXT_VALUE,
  ResourceFormContext,
} from './ResourceFormContext';

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
  onSave?: () => void;
  onCancel?: () => void;
  onValidationChange?: (valid: boolean) => void;
}

const nonEssentialProps: string[] = [
  core.properties.isA,
  core.properties.parent,
  core.properties.write,
  core.properties.read,
  commits.properties.lastCommit,
  dataBrowser.properties.subResources,
];

/** Form for editing and creating a Resource */
export function ResourceForm({
  classSubject,
  resource,
  variant = ResourceFormVariant.Default,
  onSave,
  onCancel,
  onValidationChange,
}: ResourceFormProps): JSX.Element {
  const isOnline = useOnline();
  const navigate = useNavigate();
  const [isAArray] = useArray(resource, core.properties.isA);

  if (classSubject === undefined && isAArray?.length > 0) {
    // This is not entirely accurate, as Atomic Data supports having multiple
    // classes for a single resource.
    classSubject = isAArray[0];
  }

  const [isFormValid, setIsFormValid] = useState(false);

  const klass = useResource(classSubject);
  const [requires] = useArray(klass, core.properties.requires);
  const [recommends] = useArray(klass, core.properties.recommends);
  const [newPropErr, setNewPropErr] = useState<Error | undefined>(undefined);
  /** A list of custom properties, set by the User while editing this form */
  const [tempOtherProps, setTempOtherProps] = useState<string[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const store = useStore();
  const wasNew: boolean = resource.new;

  const onSaveSuccess = useCallback(() => {
    // We need to read the earlier .new state, because the resource is no
    // longer new after it was saved, during this callback
    wasNew && store.notifyResourceManuallyCreated(resource);
    onSave?.();
    navigate(constructOpenURL(resource.subject));
  }, [resource, store, wasNew, onSave, navigate]);

  const [save, saving, err] = useSaveResource(resource, onSaveSuccess);

  const [canWrite, canWriteErr] = useCanWrite(resource);

  const otherProps = useMemo(() => {
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

    return [...prps, ...tempOtherProps];
    // I actually want to run this memo every time the requires / recommends
    // array changes, but that leads to a weird loop, so that's what the length is for
  }, [resource, tempOtherProps, requires.length, recommends.length]);

  const handleValidate = useCallback(
    (valid: boolean) => {
      setIsFormValid(valid);
      onValidationChange?.(valid);
    },
    [onValidationChange],
  );

  const handleDelete = useCallback(
    (propertyURL: string) => {
      resource.remove(propertyURL);
      setTempOtherProps(tempOtherProps.filter(prop => prop !== propertyURL));
    },
    [resource, tempOtherProps],
  );

  if (!resource.new && resource.loading) {
    return <>Loading resource...</>;
  }

  if (resource.error) {
    return <ErrMessage>{resource.error.message}</ErrMessage>;
  }

  if (klass.loading) {
    return <>Loading class...</>;
  }

  if (!klass.hasClasses(core.classes.class)) {
    return (
      <ErrMessage>
        {classSubject} is not a Class. Only resources with valid classes can be
        created or edited at this moment.
      </ErrMessage>
    );
  }

  function handleAddProp(newProp: string | undefined) {
    setNewPropErr(undefined);

    if (!Client.isValidSubject(newProp)) {
      setNewPropErr(new Error('Invalid URL'));

      return;
    }

    if (!newProp) {
      return;
    }

    if (
      tempOtherProps.includes(newProp) ||
      requires.includes(newProp) ||
      recommends.includes(newProp)
    ) {
      setNewPropErr(
        new Error(
          'That property already exists in this resource. It can only be added once.',
        ),
      );
    } else {
      setTempOtherProps(prev => [...prev, newProp]);
    }
  }

  return (
    <ResourceFormContext.Provider value={RESOURCE_FORM_CONTEXT_VALUE}>
      <FormValidationContextProvider onValidationChange={handleValidate}>
        <form about={resource.subject} onSubmit={save}>
          <Column>
            {classSubject && klass.error && (
              <ErrMessage>
                Error in class, so this form could miss properties. You can
                still edit the resource, though. Error message: `
                {klass.error.message}`
              </ErrMessage>
            )}
            {canWriteErr && (
              <ErrMessage>Cannot save edits: {canWriteErr}</ErrMessage>
            )}
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
          </Column>
          <Gutter />
          <Button
            title={'show / hide advanced form fields'}
            clean
            onClick={() => setShowAdvanced(!showAdvanced)}
          >
            <Row as='strong' gap='0.4rem' center>
              {showAdvanced ? <FaCaretDown /> : <FaCaretRight />} Advanced
            </Row>
          </Button>
          <StyledCollapse open={showAdvanced}>
            <Column>
              <Field
                label='add another property...'
                helper='In Atomic Data, any Resource could have any single Property. Use this field to add new property-value combinations to your resource.'
              >
                <div>
                  <ResourceSelector
                    value={undefined}
                    setSubject={set => {
                      handleAddProp(set);
                    }}
                    isA={core.classes.property}
                  />
                </div>
                {newPropErr && <ErrMessage>{newPropErr.message}</ErrMessage>}
              </Field>
              {nonEssentialProps.map(prop => (
                <ResourceField
                  key={prop}
                  propertyURL={prop}
                  resource={resource}
                />
              ))}
            </Column>
          </StyledCollapse>
          {variant !== ResourceFormVariant.Dialog && (
            <>
              <Row justify='flex-end' center wrapItems>
                {err && <InlineErrMessage>{err.message}</InlineErrMessage>}
                {!isOnline && (
                  <InlineErrMessage>
                    You are offline, changes can not be saved
                  </InlineErrMessage>
                )}
                {onCancel && (
                  <Button subtle onClick={onCancel}>
                    Cancel
                  </Button>
                )}
                <Button
                  disabled={saving || !isFormValid || !isOnline || !canWrite}
                  data-test='save'
                  type='submit'
                >
                  <FaFloppyDisk />
                  {saving ? 'wait...' : 'Save'}
                </Button>
              </Row>
            </>
          )}
        </form>
      </FormValidationContextProvider>
    </ResourceFormContext.Provider>
  );
}

const StyledCollapse = styled(Collapse)`
  margin-top: ${p => (p.open ? '1rem' : '0')};
`;
