import { useState, type JSX } from 'react';
import { useString, validateDatatype } from '@tomic/react';
import { InputProps } from './ResourceField';
import { InputStyled, InputWrapper } from './InputStyles';
import { slugWhileTyping, stringToSlug } from '../../helpers/stringToSlug';
import {
  checkForInitialRequiredValue,
  useValidation,
} from './formValidation/useValidation';
import { styled } from 'styled-components';
import { ErrorChipInput } from './ErrorChip';

export default function InputSlug({
  resource,
  property,
  commit,
  commitDebounceInterval,
  ...props
}: InputProps): JSX.Element {
  const [value, setValue] = useString(resource, property.subject, {
    validate: false,
    commit,
    commitDebounce: commitDebounceInterval,
  });

  const { error, setError, setTouched } = useValidation(
    checkForInitialRequiredValue(value, props.required),
  );

  const [inputValue, setInputValue] = useState(value);

  function handleBlur(event: React.FocusEvent<HTMLInputElement>): void {
    // Settle the value: a dash left dangling by `slugWhileTyping` is not valid
    // on its own, so it goes once the field is done being typed into.
    const settled = stringToSlug(event.target.value);

    if (settled !== inputValue) {
      setInputValue(settled);
      setValue(settled === '' ? undefined : settled);
    }

    setTouched();
  }

  function handleUpdate(event: React.ChangeEvent<HTMLInputElement>): void {
    const newValue = slugWhileTyping(event.target.value);
    setInputValue(newValue);

    // Validate and store the settled form, not the one on screen: a value
    // ending in the dash you are still typing is not a valid slug, and
    // validating it would flash "Invalid Slug" between every hyphenated word.
    const settled = stringToSlug(event.target.value);

    setError(undefined);

    try {
      if (settled === '') {
        setValue(undefined);
      } else {
        validateDatatype(settled, property.datatype);
        setValue(settled);
      }
    } catch (e) {
      setError('Invalid Slug');
    }

    if (props.required && settled === '') {
      setError('Required');
    }
  }

  return (
    <Wrapper>
      <InputWrapper $invalid={!!error}>
        <InputStyled
          type='text'
          value={inputValue ?? ''}
          onChange={handleUpdate}
          onBlur={handleBlur}
          autoComplete='none'
          {...props}
        />
      </InputWrapper>
      {error && <ErrorChipInput top='2rem'>{error}</ErrorChipInput>}
    </Wrapper>
  );
}

const Wrapper = styled.div`
  flex: 1;
  position: relative;
`;
