import { JSONValue } from '@tomic/react';

import { Checkbox } from '@components/forms/Checkbox';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';

import type { JSX } from 'react';

function BooleanCellEdit({
  value,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  return <Checkbox autoFocus checked={Boolean(value)} onChange={onChange} />;
}

function BooleanCellDisplay({
  value,
  onChange,
}: DisplayCellProps<JSONValue>): JSX.Element {
  return <Checkbox checked={Boolean(value)} onChange={onChange} />;
}

export const BooleanCell: CellContainer<JSONValue> = {
  Edit: BooleanCellEdit,
  Display: BooleanCellDisplay,
};
