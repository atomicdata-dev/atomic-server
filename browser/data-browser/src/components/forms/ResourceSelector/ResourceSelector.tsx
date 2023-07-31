import { urls, useArray, useResource, useStore, useTitle } from '@tomic/react';
import React, { useState, useCallback, useReducer } from 'react';
import { ErrMessage, InputWrapper } from '../InputStyles';
import { DropdownInput } from './DropdownInput';
import { Dialog, useDialog } from '../../Dialog';
import { useDialogTreeContext } from '../../Dialog/dialogContext';
import { useSettings } from '../../../helpers/AppSettings';
import styled from 'styled-components';
import { NewFormDialog } from '../NewForm/NewFormDialog';
import { useDeferredUpdate } from '../../../hooks/useDeferredUpdate';
import { ErrorChip } from '../ErrorChip';

type SetSubject = (subject: string | undefined) => void;

interface ResourceSelectorProps {
  /**
   * Whether a certain type of Class is required here. Pass the URL of the
   * class. Is used for constructing a list of options.
   */
  classType?: string;
  /** If true, the form will show an error if it is left empty. */
  required?: boolean;
  /**
   * This callback is called when the Subject Changes. You can pass an Error
   * Handler as the second argument to set an error message. Take the second
   * argument of a `useString` hook and pass the setString part to this property
   */
  setSubject: SetSubject;
  /** The value (URL of the Resource that is selected) */
  value?: string;
  /** A function to remove this item. Only relevant in arrays. */
  handleRemove?: () => void;
  /** Only pass an error if it is applicable to this specific field */
  error?: Error;
  onValidate?: (e: Error | undefined) => void;
  disabled?: boolean;
  autoFocus?: boolean;
  /** Is used when a new item is created using the ResourceSelector */
  parent?: string;
  hideCreateOption?: boolean;
}

/**
 * Form field for selecting a single resource. Needs external subject &
 * setSubject properties
 */
export const ResourceSelector = React.memo(function ResourceSelector({
  required,
  setSubject,
  value,
  handleRemove,
  classType,
  disabled,
  onValidate,
  parent,
  hideCreateOption,
  ...props
}: ResourceSelectorProps): JSX.Element {
  // TODO: This list should use the user's Pod instead of a hardcoded collection;
  const classesCollection = useResource(getCollectionURL(classType));
  const [touched, handleBlur] = useReducer(() => true, false);
  const [error, setError] = useState<string>();
  let [options] = useArray(
    classesCollection,
    urls.properties.collection.members,
  );
  const requiredClass = useResource(classType);
  const [classTypeTitle] = useTitle(requiredClass);
  const store = useStore();
  const [dialogProps, showDialog, closeDialog, isDialogOpen] = useDialog();
  const { drive } = useSettings();

  const [
    /** The value of the input underneath, updated through a callback */
    inputValue,
    setInputValue,
  ] = useState(value || '');

  const updateSubject = useDeferredUpdate(
    setSubject,
    inputValue as string | undefined,
  );

  const handleUpdate = useCallback(
    (newValue: string | undefined) => {
      setError(undefined);
      updateSubject(newValue);
    },
    [updateSubject],
  );

  const onInputChange = useCallback(
    (str: string) => {
      setInputValue(str);

      try {
        new URL(str);
        updateSubject(str);
        setError(undefined);
      } catch (e) {
        // Don't cause state changes when the value didn't change.
        if (value !== undefined) {
          updateSubject(undefined);
        }

        if (str !== '') {
          setError('Invalid URL');
        } else {
          setError(undefined);
        }
      }
    },
    [setInputValue, updateSubject, onValidate],
  );

  const { inDialog } = useDialogTreeContext();

  if (options.length === 0) {
    options = store.getAllSubjects();
  }

  let placeholder = 'Enter an Atomic URL...';

  if (classType && classTypeTitle?.length > 0) {
    placeholder = `Select a ${classTypeTitle} or enter a ${classTypeTitle} URL...`;
  }

  if (classType && !requiredClass.isReady()) {
    placeholder = 'Loading Class...';
  }

  return (
    <Wrapper>
      <DropdownInput
        invalid={!!error}
        placeholder={placeholder}
        required={required}
        onUpdate={handleUpdate}
        options={options}
        onRemove={handleRemove}
        initial={value}
        disabled={disabled}
        classType={classType}
        onCreateClick={hideCreateOption ? undefined : showDialog}
        onBlur={handleBlur}
        onInputChange={onInputChange}
        {...props}
      />
      {touched && error && (
        <PositionedErrorChip noMovement>{error}</PositionedErrorChip>
      )}
      {!inDialog && (
        <Dialog {...dialogProps}>
          {isDialogOpen && (
            <NewFormDialog
              parent={parent || drive}
              // I don't think we know for sure that there is a classType known here
              classSubject={classType!}
              closeDialog={closeDialog}
              initialTitle={inputValue!}
              onSave={updateSubject}
            />
          )}
        </Dialog>
      )}
      {required && value === '' && <ErrMessage>Required</ErrMessage>}
    </Wrapper>
  );
});

/** For a given class URL, this tries to return a URL of a Collection containing these. */
// TODO: Scope to current store / make adjustable https://github.com/atomicdata-dev/atomic-data-browser/issues/295
export function getCollectionURL(classtypeUrl?: string): string | undefined {
  switch (classtypeUrl) {
    case urls.classes.property:
      return 'https://atomicdata.dev/properties/?page_size=999';
    case urls.classes.class:
      return 'https://atomicdata.dev/classes/?page_size=999';
    case urls.classes.agent:
      return 'https://atomicdata.dev/agents/';
    case urls.classes.commit:
      return 'https://atomicdata.dev/commits';
    case urls.classes.datatype:
      return 'https://atomicdata.dev/datatypes';
    default:
      return undefined;
  }
}

const Wrapper = styled.div`
  flex: 1;
  position: relative;
  --radius: ${props => props.theme.radius};
  ${InputWrapper} {
    border-radius: 0;
  }

  &:first-of-type ${InputWrapper} {
    border-top-left-radius: var(--radius);
    border-top-right-radius: var(--radius);
  }

  &:last-of-type ${InputWrapper} {
    border-bottom-left-radius: var(--radius);
    border-bottom-right-radius: var(--radius);
  }

  &:not(:last-of-type) ${InputWrapper} {
    border-bottom: none;
  }
`;

const PositionedErrorChip = styled(ErrorChip)`
  position: absolute;
  top: 2rem;
  z-index: 100;
`;
