import {
  JSONValue,
  urls,
  useNumber,
  useResource,
  useString,
} from '@tomic/react';
import React from 'react';
import styled from 'styled-components';
import { InputBase } from './InputBase';
import { ProgressBar } from './ProgressBar';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';

const { numberFormats } = urls.instances;

function formatValue(
  value: number | undefined,
  numberFormatting: string | undefined,
  decimalPlaces: number | undefined,
) {
  const isPercentage = numberFormatting === numberFormats.percentage;
  const suffix = isPercentage ? ' %' : '';

  const formattedValue =
    decimalPlaces !== undefined ? value?.toFixed(decimalPlaces) : value;

  return `${formattedValue}${suffix}`;
}

function FloatCellEdit({
  value,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  return (
    <InputBase
      value={value as number}
      type='number'
      autoFocus
      onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
        const num = Number.parseFloat(e.target.value);

        if (Number.isNaN(num)) {
          return onChange(undefined);
        }

        return onChange(num);
      }}
    />
  );
}

function FloatCellDisplay({
  value,
  property,
}: DisplayCellProps<JSONValue>): JSX.Element {
  const propertyResource = useResource(property);
  const [numberFormatting] = useString(
    propertyResource,
    urls.properties.constraints.numberFormatting,
  );
  const [decimalPlaces] = useNumber(
    propertyResource,
    urls.properties.constraints.decimalPlaces,
  );

  const isPercentage = numberFormatting === numberFormats.percentage;

  const formattedValue = formatValue(
    value as number | undefined,
    numberFormatting,
    decimalPlaces,
  );

  return (
    <>
      <Aligned>{value !== undefined && formattedValue}</Aligned>
      {isPercentage && <ProgressBar percentage={value as number} />}
    </>
  );
}

export const FloatCell: CellContainer<JSONValue> = {
  Edit: FloatCellEdit,
  Display: FloatCellDisplay,
};

const Aligned = styled.span`
  text-align: end;
  display: inline-block;
  width: 100%;
`;
