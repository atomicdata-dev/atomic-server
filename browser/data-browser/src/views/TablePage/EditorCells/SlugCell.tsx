import { JSONValue } from '@tomic/react';
import React, { useCallback } from 'react';
import { InputBase } from './InputBase';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';

function SlugCellEdit({
  value,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const v = e.target.value.toLowerCase().replace(/\s/g, '-');
      onChange(v);
    },
    [onChange],
  );

  return (
    <InputBase value={value as string} autoFocus onChange={handleChange} />
  );
}

function SlugCellDisplay({ value }: DisplayCellProps<JSONValue>): JSX.Element {
  return <>{value}</>;
}

export const SlugCell: CellContainer<JSONValue> = {
  Edit: SlugCellEdit,
  Display: SlugCellDisplay,
};
