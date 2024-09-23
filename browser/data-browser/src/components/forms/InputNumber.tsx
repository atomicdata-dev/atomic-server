import { Datatype, useNumber, validateDatatype } from '@tomic/react';
import { InputProps } from './ResourceField';
import { InputStyled, InputWrapper } from './InputStyles';
import {
  checkForInitialRequiredValue,
  useValidation,
} from './formValidation/useValidation';
import { ErrorChipInput } from './ErrorChip';
import { styled } from 'styled-components';

export default function InputNumber({
  resource,
  property,
  commit,
  ...props
}: InputProps): JSX.Element {
  const [value, setValue] = useNumber(resource, property.subject, {
    validate: false,
    commit,
  });

  const { error, setError, setTouched } = useValidation(
    checkForInitialRequiredValue(value, props.required),
  );

  function handleUpdate(e: React.ChangeEvent<HTMLInputElement>) {
    setError(undefined);

    if (e.target.value === '') {
      if (props.required) {
        setError('Required');
      }

      setValue(undefined);
    } else {
      try {
        const newVal = +e.target.value;
        validateDatatype(newVal, property.datatype);
        setValue(newVal);
      } catch (er) {
        setError('Invalid Number');
      }
    }

    if (props.required && e.target.value === '') {
      setError('Required');
    }
  }

  return (
    <Wrapper>
      <InputWrapper $invalid={!!error}>
        <InputStyled
          placeholder='Enter a number...'
          type='number'
          value={value === undefined ? '' : Number.isNaN(value) ? '' : value}
          step={property.datatype === Datatype.INTEGER ? 1 : 'any'}
          onChange={handleUpdate}
          onBlur={setTouched}
          {...props}
        />
      </InputWrapper>
      {error && <ErrorChipInput top='2rem'>{error}</ErrorChipInput>}
    </Wrapper>
  );
}

const Wrapper = styled.div`
  flex: 1;
  width: fit-content;
  position: relative;
`;
