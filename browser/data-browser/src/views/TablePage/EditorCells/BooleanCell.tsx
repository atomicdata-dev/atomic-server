import { JSONValue } from '@tomic/react';

import { Checkbox } from '../../../components/forms/Checkbox';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';

function BooleanCellEdit({
  value,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  return <Checkbox autoFocus checked={value as boolean} onChange={onChange} />;
}

function BooleanCellDisplay({
  value,
  onChange,
}: DisplayCellProps<JSONValue>): JSX.Element {
  return <Checkbox checked={value as boolean} onChange={onChange} />;
}

export const BooleanCell: CellContainer<JSONValue> = {
  Edit: BooleanCellEdit,
  Display: BooleanCellDisplay,
};
