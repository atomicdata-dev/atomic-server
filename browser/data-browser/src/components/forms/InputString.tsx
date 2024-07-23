import { useString, validateDatatype } from '@tomic/react';
import { InputProps } from './ResourceField';
import { InputStyled, InputWrapper } from './InputStyles';
import { styled } from 'styled-components';
import { ErrorChipInput } from './ErrorChip';
import { useValidation } from './formValidation/useValidation';

export default function InputString({
  resource,
  property,
  commit,
  commitDebounceInterval,
  ...props
}: InputProps): JSX.Element {
  const [err, setErr, onBlur] = useValidation();
  const [value, setValue] = useString(resource, property.subject, {
    commit,
    commitDebounce: commitDebounceInterval,
    validate: false,
  });

  function handleUpdate(event: React.ChangeEvent<HTMLInputElement>): void {
    const newval = event.target.value || undefined;
    setValue(newval);

    try {
      validateDatatype(newval, property.datatype);
      setErr(undefined);
    } catch (e) {
      setErr('Invalid value');
    }

    if (props.required && newval === '') {
      setErr('Required');
    }
  }

  return (
    <Wrapper>
      <InputWrapper $invalid={!!err}>
        <InputStyled
          value={value === undefined ? '' : value}
          onChange={handleUpdate}
          {...props}
          onBlur={onBlur}
        />
      </InputWrapper>
      {err && <ErrorChipInput>{err}</ErrorChipInput>}
    </Wrapper>
  );
}

const Wrapper = styled.div`
  flex: 1;
  position: relative;
`;
