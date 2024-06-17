import { Datatype, useNumber, validateDatatype } from '@tomic/react';
import { InputProps } from './ResourceField';
import { InputStyled, InputWrapper } from './InputStyles';
import { useValidation } from './formValidation/useValidation';
import { ErrorChipInput } from './ErrorChip';
import { styled } from 'styled-components';

export default function InputNumber({
  resource,
  property,
  commit,
  ...props
}: InputProps): JSX.Element {
  const [err, setErr, onBlur] = useValidation();
  const [value, setValue] = useNumber(resource, property.subject, {
    handleValidationError: setErr,
    validate: false,
    commit,
  });

  function handleUpdate(e: React.ChangeEvent<HTMLInputElement>) {
    setErr(undefined);

    if (e.target.value === '') {
      if (props.required) {
        setErr('Required');
      }

      setValue(undefined);
    } else {
      try {
        const newVal = +e.target.value;
        validateDatatype(newVal, property.datatype);
        setValue(newVal);
      } catch (er) {
        setErr('Invalid Number');
      }
    }

    if (props.required && e.target.value === '') {
      setErr('Required');
    }
  }

  return (
    <Wrapper>
      <InputWrapper $invalid={!!err}>
        <InputStyled
          placeholder='Enter a number...'
          type='number'
          value={value === undefined ? '' : Number.isNaN(value) ? '' : value}
          step={property.datatype === Datatype.INTEGER ? 1 : 'any'}
          onChange={handleUpdate}
          onBlur={onBlur}
          {...props}
        />
      </InputWrapper>
      {err && <ErrorChipInput top='2rem'>{err}</ErrorChipInput>}
    </Wrapper>
  );
}

const Wrapper = styled.div`
  flex: 1;
  width: fit-content;
  position: relative;
`;
