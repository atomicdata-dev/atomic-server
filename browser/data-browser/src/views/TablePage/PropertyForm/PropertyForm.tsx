import { core, Resource, useString } from '@tomic/react';
import { useCallback, useEffect, useMemo } from 'react';
import { styled } from 'styled-components';
import { ErrorChip } from '../../../components/forms/ErrorChip';
import { useValidation } from '../../../components/forms/formValidation/useValidation';
import {
  InputStyled,
  InputWrapper,
} from '../../../components/forms/InputStyles';
import { stringToSlug } from '../../../helpers/stringToSlug';
import { categoryFormFactory, PropertyFormCategory } from './categories';

interface PropertyFormProps {
  onSubmit: () => void;
  resource: Resource;
  category?: PropertyFormCategory;
  existingProperty?: boolean;
}

export function PropertyForm({
  resource,
  onSubmit,
  existingProperty,
  category,
}: PropertyFormProps): JSX.Element {
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
    [],
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
      const newShortName = stringToSlug((value ?? '').trim());

      setName(value);
      setShortName(newShortName);
    },
    [setName, setShortName],
  );

  const handleSubmit: React.FormEventHandler<HTMLFormElement> = useCallback(
    e => {
      e.preventDefault();
      onSubmit();
    },
    [onSubmit],
  );

  // If name was already set remove the error.
  useEffect(() => {
    if (existingProperty && !name && shortname) {
      setName(shortname);
      setNameError(undefined);
    }

    if (name) {
      setNameError(undefined);
    }
  }, []);

  const CategoryForm = categoryFormFactory(category);

  return (
    <Form onSubmit={handleSubmit}>
      <div>
        <InputWrapper $invalid={!!nameError}>
          <InputStyled
            id='name-form'
            type='text'
            value={name}
            onChange={handleNameChange}
            placeholder='New Column'
            onBlur={setNameTouched}
          />
        </InputWrapper>
        {nameError && <ErrorChip>{nameError}</ErrorChip>}
      </div>
      <CategoryForm resource={resource} />
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
