import {
  isNumber,
  JSONValue,
  urls,
  useResource,
  useString,
} from '@tomic/react';
import { useEffect, useState } from 'react';
import { formatDate } from '../../../helpers/dates/formatDate';
import { InputBase } from './InputBase';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';
import { useDateTimeInput } from '../../../components/forms/hooks/useDateTimeInput';

function DateTimeCellEdit({
  value,
  onChange,
}: EditCellProps<JSONValue>): JSX.Element {
  const [localDate, handleChange] = useDateTimeInput(value as number, onChange);

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
