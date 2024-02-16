import { isNumber } from '@tomic/react';
import { useCallback } from 'react';

const pad = (value: number): string => `${value}`.padStart(2, '0');

const timestampToDateTimeLocal = (timestamp: number): string => {
  const date = new Date(timestamp);

  const year = date.getFullYear();
  const month = date.getMonth() + 1;
  const day = date.getDate();
  const hours = date.getHours();
  const minutes = date.getMinutes();

  return `${year}-${pad(month)}-${pad(day)}T${pad(hours)}:${pad(minutes)}`;
};

const dateTimeLocalToTimestamp = (dateTimeLocal: string): number => {
  const date = new Date(dateTimeLocal);

  return date.getTime();
};

export const useDateTimeInput = (
  value: number | undefined,
  onChange: (value: number | undefined) => void,
): [
  localDate: string | undefined,
  handleChange: (e: React.ChangeEvent<HTMLInputElement>) => void,
] => {
  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.value) {
        onChange(dateTimeLocalToTimestamp(e.target.value));
      } else {
        onChange(undefined);
      }
    },
    [onChange],
  );

  let localDate: string | undefined = undefined;

  if (isNumber(value)) {
    localDate = timestampToDateTimeLocal(value);
  }

  return [localDate, handleChange];
};
