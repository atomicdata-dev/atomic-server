import { JSONValue, urls, useResource, useString } from '@tomic/react';

import { styled } from 'styled-components';
import { InputBase } from './InputBase';
import { ProgressBar } from './ProgressBar';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';

const { numberFormats } = urls.instances;

function IntegerCellEdit({
  value,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  return (
    <InputBase
      value={value as number}
      type='number'
      autoFocus
      onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
        const num = Number.parseInt(e.target.value);

        if (Number.isNaN(num)) {
          return onChange(undefined);
        }

        return onChange(num);
      }}
    />
  );
}

function IntegerCellDisplay({
  value,
  property,
}: DisplayCellProps<JSONValue>): JSX.Element {
  const propertyResource = useResource(property);
  const [numberFormatting] = useString(
    propertyResource,
    urls.properties.constraints.numberFormatting,
  );

  const isPercentage = numberFormatting === numberFormats.percentage;
  const suffix = isPercentage ? ' %' : '';

  return (
    <>
      <Aligned>{value && `${value}${suffix}`}</Aligned>
      {isPercentage && <ProgressBar percentage={value as number} />}
    </>
  );
}

export const IntegerCell: CellContainer<JSONValue> = {
  Edit: IntegerCellEdit,
  Display: IntegerCellDisplay,
};

const Aligned = styled.span`
  text-align: end;
  display: inline-block;
  width: 100%;
`;
