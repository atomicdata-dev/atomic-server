import { JSONValue } from '@tomic/react';

import { InputBase } from './InputBase';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';

import { useState, type JSX } from 'react';

function StringCellEdit({
  value,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  // Mirror the value in synchronous local state. Binding the input straight
  // to the async resource `value` means a keystroke that hasn't yet
  // round-tripped through `setValue` + rerender gets reset to the stale
  // value, dropping/interleaving characters under load. Local state updates
  // on the keystroke itself, so the input never lags; `onChange` still
  // propagates each keystroke to the resource. A fresh input (with fresh
  // local state seeded from `value`) mounts per edit session via the
  // `isEditing` toggle.
  const [localValue, setLocalValue] = useState<string>((value as string) ?? '');

  return (
    <InputBase
      value={localValue ?? ''}
      autoFocus
      onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
        setLocalValue(e.target.value);
        onChange(e.target.value);
      }}
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
