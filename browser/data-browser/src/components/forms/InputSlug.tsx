import { useState, type JSX } from 'react';
import { useString } from '@tomic/react';
import { InputProps } from './ResourceField';
import { InputStyled, InputWrapper } from './InputStyles';
import { slugWhileTyping, stringToSlug } from '../../helpers/stringToSlug';
import { useValidatedInput } from './formValidation/useValidatedInput';
import { styled } from 'styled-components';
import { ErrorChipInput } from './ErrorChip';

export default function InputSlug({
  resource,
  property,
  commit,
  commitDebounceInterval,
  required,
  ...props
}: InputProps): JSX.Element {
  const [value, setValue] = useString(resource, property.subject, {
    validate: false,
    commit,
    commitDebounce: commitDebounceInterval,
  });

  const { error, setTouched, update } = useValidatedInput(value, setValue, {
    datatype: property.datatype,
    required,
  });

  const [inputValue, setInputValue] = useState(value);

  function handleBlur(event: React.FocusEvent<HTMLInputElement>): void {
    // Settle the value: a dash left dangling by `slugWhileTyping` is not valid
    // on its own, so it goes once the field is done being typed into.
    const settled = stringToSlug(event.target.value);

    if (settled !== inputValue) {
      setInputValue(settled);
      update(settled === '' ? undefined : settled);
    }

    setTouched();
  }

  function handleUpdate(event: React.ChangeEvent<HTMLInputElement>): void {
    setInputValue(slugWhileTyping(event.target.value));

    // Validate and store the settled form, not the one on screen: a value
    // ending in the dash you are still typing is not a valid slug, and
    // validating it would flash an error between every hyphenated word.
    const settled = stringToSlug(event.target.value);
    update(settled === '' ? undefined : settled);
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
          required={required}
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
