import { Resource, urls, useString } from '@tomic/react';
import { useCallback, useEffect, useMemo } from 'react';
import { styled } from 'styled-components';
import { ErrorChip } from '../../../components/forms/ErrorChip';
import { useValidation } from '../../../components/forms/formValidation/useValidation';
import {
  InputStyled,
  InputWrapper,
} from '../../../components/forms/InputStyles';
import { buildComponentFactory } from '../../../helpers/buildComponentFactory';
import { stringToSlug } from '../../../helpers/stringToSlug';
import { CheckboxPropertyForm } from './CheckboxPropertyForm';
import { DatePropertyForm } from './DatePropertyForm';
import { FilePropertyForm } from './FilePropertyForm';
import { NumberPropertyForm } from './NumberPropertyForm';
import { RelationPropertyForm } from './RelationPropertyForm';
import { SelectPropertyForm } from './SelectPropertyForm';
import { TextPropertyForm } from './TextPropertyForm';

export type PropertyFormCategory =
  | 'text'
  | 'number'
  | 'date'
  | 'checkbox'
  | 'file'
  | 'select'
  | 'relation';

interface PropertyFormProps {
  onSubmit: () => void;
  resource: Resource;
  category?: PropertyFormCategory;
}

export const getCategoryFromDatatype = (
  datatype: string | undefined,
): PropertyFormCategory => {
  switch (datatype) {
    case urls.datatypes.string:
    case urls.datatypes.markdown:
    case urls.datatypes.slug:
      return 'text';
    case urls.datatypes.integer:
    case urls.datatypes.float:
      return 'number';
    case urls.datatypes.boolean:
      return 'checkbox';
    case urls.datatypes.date:
    case urls.datatypes.timestamp:
      return 'date';
    case urls.datatypes.resourceArray:
      return 'select';
    case urls.datatypes.atomicUrl:
      return 'relation';
  }

  throw new Error(`Unknown datatype: ${datatype}`);
};

const NoCategorySelected = () => {
  return <span>No Type selected</span>;
};

const categoryFormFactory = buildComponentFactory(
  new Map([
    ['text', TextPropertyForm],
    ['number', NumberPropertyForm],
    ['checkbox', CheckboxPropertyForm],
    ['select', SelectPropertyForm],
    ['date', DatePropertyForm],
    ['file', FilePropertyForm],
    ['relation', RelationPropertyForm],
  ]),
  NoCategorySelected,
);

export function PropertyForm({
  resource,
  onSubmit,
  category,
}: PropertyFormProps): JSX.Element {
  const [nameError, setNameError, onNameBlur] = useValidation('Required');

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
    urls.properties.name,
    valueOptions,
  );
  const [_, setShortName] = useString(
    resource,
    urls.properties.shortname,
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

  // If name was already set remove the error.
  useEffect(() => {
    if (name) {
      setNameError(undefined);
    }
  }, []);

  const CategoryForm = categoryFormFactory(category);

  return (
    <Form
      onSubmit={e => {
        e.preventDefault();
        onSubmit();
      }}
    >
      <div>
        <InputWrapper $invalid={!!nameError}>
          <InputStyled
            type='text'
            value={name}
            onChange={handleNameChange}
            placeholder='New Column'
            onBlur={onNameBlur}
          />
        </InputWrapper>
        {nameError && <ErrorChip>{nameError}</ErrorChip>}
      </div>
      <CategoryForm resource={resource} />
    </Form>
  );
}

const Form = styled.form`
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;
