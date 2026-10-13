import { core, Resource, unknownSubject, useString } from '@tomic/react';
import { useCallback, useEffect, useMemo, useRef, type JSX } from 'react';
import { styled } from 'styled-components';
import { ErrorChip } from '@components/forms/ErrorChip';
import { useValidation } from '@components/forms/formValidation/useValidation';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { stringToSlug } from '@helpers/stringToSlug';
import { categoryFormFactory, PropertyFormCategory } from './categories';

interface PropertyFormProps {
  onSubmit: () => void;
  resource: Resource;
  category?: PropertyFormCategory;
  existingProperty?: boolean;
  autoFocusName?: boolean;
}

export function PropertyForm({
  resource,
  onSubmit,
  existingProperty,
  category,
  autoFocusName,
}: PropertyFormProps): JSX.Element {
  const nameInputRef = useRef<HTMLInputElement>(null);
  const {
    error: nameError,
    setError: setNameError,
    setTouched: setNameTouched,
  } = useValidation('Required');

  const valueOptions = useMemo(
    () => ({
      handleValidationError(e: Error | undefined) {
        if (e) {
          setNameError('Invalid Name');
        } else {
          setNameError(undefined);
        }
      },
    }),
    [setNameError],
  );

  const [name, setName] = useString(
    resource,
    core.properties.name,
    valueOptions,
  );
  const [shortname, setShortName] = useString(
    resource,
    core.properties.shortname,
    valueOptions,
  );

  const handleNameChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const value = e.target.value;

      setName(value);

      // The shortname is part of the property's identity, so it only follows
      // the name while the property is being created. Renaming an existing
      // property changes the label only.
      if (!existingProperty) {
        setShortName(stringToSlug((value ?? '').trim()));
      }
    },
    [setName, setShortName, existingProperty],
  );

  const handleSubmit: React.FormEventHandler<HTMLFormElement> = useCallback(
    e => {
      e.preventDefault();
      onSubmit();
    },
    [onSubmit],
  );

  // Clear validation error if name is already set (pre-filled or existing property).
  useEffect(() => {
    if (
      resource.subject !== unknownSubject &&
      existingProperty &&
      !name &&
      shortname
    ) {
      setName(shortname);
      setNameError(undefined);
    }

    if (name) {
      setNameError(undefined);
    }
  }, []);

  useEffect(() => {
    if (!autoFocusName) {
      return;
    }

    const timeout = window.setTimeout(() => {
      nameInputRef.current?.focus();
      nameInputRef.current?.select();
    }, 0);

    return () => {
      window.clearTimeout(timeout);
    };
  }, [autoFocusName, resource.subject]);

  const CategoryForm = categoryFormFactory(category);

  return (
    <Form onSubmit={handleSubmit}>
      <div>
        <InputWrapper $invalid={!!nameError}>
          <InputStyled
            ref={nameInputRef}
            id='name-form'
            type='text'
            autoFocus={autoFocusName}
            data-dialog-autofocus={autoFocusName ? true : undefined}
            value={name ?? ''}
            onChange={handleNameChange}
            placeholder='New Column'
            onFocus={autoFocusName ? e => e.currentTarget.select() : undefined}
            onBlur={setNameTouched}
          />
        </InputWrapper>
        {nameError && <ErrorChip>{nameError}</ErrorChip>}
      </div>
      <CategoryForm resource={resource} existingProperty={existingProperty} />
      {/* Needed for inputs to submit on enter */}
      <HiddenSubmitButton type='submit' />
    </Form>
  );
}

const Form = styled.form`
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;

const HiddenSubmitButton = styled.button`
  display: none;
`;
