import { urls } from '@tomic/react';
import { buildFormatters } from './formatters';
import { toRelativeDateTime } from './relativeDate';

const {
  instances: { dateFormats },
} = urls;

export function formatDate(
  formatting: string,
  date: Date,
  withTime: boolean,
): string {
  const { longDateFormatter, numericDateFormatter } = buildFormatters(withTime);

  switch (formatting) {
    case dateFormats.localLong:
      return longDateFormatter.format(date);
    case dateFormats.localNumeric:
      return numericDateFormatter.format(date);
    case dateFormats.localRelative:
      return toRelativeDateTime(date, withTime);
    default:
      throw new Error(`Unknown formatting: ${formatting}`);
  }
}
