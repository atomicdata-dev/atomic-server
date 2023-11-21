import {
  Datatype,
  isString,
  JSONValue,
  urls,
  useResource,
  useString,
  validateDatatype,
} from '@tomic/react';
import { useCallback, useEffect, useState } from 'react';
import { formatDate } from '../../../helpers/dates/formatDate';
import { InputBase } from './InputBase';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';

function DateCellEdit({
  value,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  const [innerValue, setInnerValue] = useState<string | undefined>(
    value as string,
  );

  // We hanlde changes ourselfs and keep a seperate state so the input can be invalid while the user is still filling in the date.
  // Only once the date is valid is the value send to the server.
  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setInnerValue(e.target.value);

      try {
        validateDatatype(e.target.value, Datatype.DATE);
        onChange(e.target.value);
      } catch (err) {
        // Do nothing.
      }
    },
    [onChange],
  );

  useEffect(() => {
    setInnerValue(value as string);
  }, [value]);

  return (
    <InputBase
      type='date'
      value={innerValue}
      autoFocus
      onChange={handleChange}
    />
  );
}

const toDisplayData = (value: JSONValue, format: string) => {
  if (isString(value)) {
    const valueWithTime = `${value}T00:00:00`;
    const date = new Date(valueWithTime);

    return formatDate(format, date, false);
  }
};

function DateCellDisplay({
  value,
  property,
}: DisplayCellProps<JSONValue>): JSX.Element {
  const propertyResource = useResource(property);
  const [format] = useString(
    propertyResource,
    urls.properties.constraints.dateFormat,
  );

  const displayData = toDisplayData(
    value,
    format ?? urls.instances.dateFormats.localNumeric,
  );

  return <>{displayData}</>;
}

export const DateCell: CellContainer<JSONValue> = {
  Edit: DateCellEdit,
  Display: DateCellDisplay,
};
