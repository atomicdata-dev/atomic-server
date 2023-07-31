import { JSONValue } from '@tomic/react';
import React from 'react';
import { InputBase } from './InputBase';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';

function StringCellEdit({
  value,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  return (
    <InputBase
      value={value as string}
      autoFocus
      onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
        onChange(e.target.value)
      }
    />
  );
}

function StringCellDisplay({
  value,
}: DisplayCellProps<JSONValue>): JSX.Element {
  return <>{value}</>;
}

export const StringCell: CellContainer<JSONValue> = {
  Edit: StringCellEdit,
  Display: StringCellDisplay,
};
