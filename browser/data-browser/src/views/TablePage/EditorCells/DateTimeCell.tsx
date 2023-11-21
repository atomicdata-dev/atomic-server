import {
  isNumber,
  JSONValue,
  urls,
  useResource,
  useString,
} from '@tomic/react';
import { useCallback, useEffect, useState } from 'react';
import { formatDate } from '../../../helpers/dates/formatDate';
import { InputBase } from './InputBase';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';

const pad = (value: number): string => `${value}`.padStart(2, '0');

const buildDateTimeLocalString = (date: Date): string => {
  const year = date.getFullYear();
  const month = date.getMonth() + 1;
  const day = date.getDate();
  const hours = date.getHours();
  const minutes = date.getMinutes();

  return `${year}-${pad(month)}-${pad(day)}T${pad(hours)}:${pad(minutes)}`;
};

function DateTimeCellEdit({
  value,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const date = new Date(e.target.value);
      onChange(date.getTime());
    },
    [onChange],
  );

  let localDate: string | undefined = undefined;

  if (isNumber(value)) {
    localDate = buildDateTimeLocalString(new Date(value));
  }

  return (
    <InputBase
      type='datetime-local'
      value={localDate}
      autoFocus
      onChange={handleChange}
    />
  );
}

const toDisplayData = (value: JSONValue, format: string, withTime: boolean) => {
  if (isNumber(value)) {
    const date = new Date(value);

    return formatDate(format, date, withTime);
  }
};

function DateTimeCellDisplay({
  value,
  property,
}: DisplayCellProps<JSONValue>): JSX.Element {
  const propertyResource = useResource(property);
  const [format] = useString(
    propertyResource,
    urls.properties.constraints.dateFormat,
  );

  const [displayData, setDisplayData] = useState(() =>
    toDisplayData(
      value,
      format ?? urls.instances.dateFormats.localNumeric,
      true,
    ),
  );

  useEffect(() => {
    setDisplayData(
      toDisplayData(
        value,
        format ?? urls.instances.dateFormats.localNumeric,
        true,
      ),
    );

    if (format === urls.instances.dateFormats.localRelative) {
      const interval = setInterval(() => {
        setDisplayData(
          toDisplayData(value, urls.instances.dateFormats.localRelative, true),
        );
      }, 1000 * 60);

      return () => clearInterval(interval);
    }
  }, [value, format]);

  return <>{displayData}</>;
}

export const DateTimeCell: CellContainer<JSONValue> = {
  Edit: DateTimeCellEdit,
  Display: DateTimeCellDisplay,
};
