import { JSONValue, isSafeHref } from '@tomic/react';
import { useCallback, type JSX } from 'react';
import { InputBase } from './InputBase';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';
import { AtomicLink } from '@components/AtomicLink';

function URICellEdit({
  value,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const v = e.target.value;
      onChange(v);
    },
    [onChange],
  );

  return (
    <InputBase
      value={(value as string | undefined) ?? ''}
      type='url'
      autoFocus
      onChange={handleChange}
    />
  );
}

function URICellDisplay({ value }: DisplayCellProps<JSONValue>): JSX.Element {
  if (!value) {
    return <></>;
  }

  const uri = value as string;

  // Shown but not linked when the scheme would run rather than navigate.
  if (!isSafeHref(uri)) {
    return <>{uri}</>;
  }

  return (
    <AtomicLink href={uri} target='_blank' rel='noopener noreferrer'>
      {uri}
    </AtomicLink>
  );
}

export const URICell: CellContainer<JSONValue> = {
  Edit: URICellEdit,
  Display: URICellDisplay,
};
