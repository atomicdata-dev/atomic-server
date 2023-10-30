import { Resource, urls, useNumber, useString } from '@tomic/react';
import React, { useCallback, useId } from 'react';
import { ErrorChip } from '../../../../components/forms/ErrorChip';
import { useValidation } from '../../../../components/forms/formValidation/useValidation';
import {
  InputStyled,
  InputWrapper,
} from '../../../../components/forms/InputStyles';
import { FormGroupHeading } from '../FormGroupHeading';

interface DecimalPlacesInputProps {
  resource: Resource;
}

export function DecimalPlacesInput({
  resource,
}: DecimalPlacesInputProps): JSX.Element {
  const id = useId();
  const [error, setError, onBlur] = useValidation();
  const [_, setDataType] = useString(resource, urls.properties.datatype, {
    commit: true,
  });

  const [__, setDecimalPlaces] = useNumber(
    resource,
    urls.properties.constraints.decimalPlaces,
    { commit: true },
  );

  const handleDecimalPointChange = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const newValue = e.target.value;
      const num = Number.parseInt(newValue, 10);

      if (num < 0) {
        setError('Value must be eighter positive, zero or empty.');
      } else {
        setError(undefined);
      }

      if (num === 0) {
        await setDataType(urls.datatypes.integer);
      } else {
        await setDataType(urls.datatypes.float);
      }

      if (isNaN(num)) {
        return await setDecimalPlaces(undefined);
      }

      setDecimalPlaces(num);
    },
    [setError],
  );

  return (
    <>
      <FormGroupHeading as='label' htmlFor={id}>
        Decimal Places
      </FormGroupHeading>
      <div>
        <InputWrapper $invalid={error !== undefined}>
          <InputStyled
            id={id}
            type='number'
            min={0}
            onBlur={onBlur}
            onChange={handleDecimalPointChange}
          />
        </InputWrapper>
        {error && <ErrorChip>{error}</ErrorChip>}
      </div>
    </>
  );
}
