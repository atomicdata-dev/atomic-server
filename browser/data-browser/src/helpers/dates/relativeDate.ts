import { buildFormatters } from './formatters';

const formatter = new Intl.RelativeTimeFormat('en', {
  localeMatcher: 'best fit', // other values: "lookup"
  numeric: 'auto', // other values: "auto"
  style: 'long', // other values: "short" or "narrow"});
});

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export function toRelativeDateTime(date: Date, withTime: boolean): string {
  if (withTime) {
    const minutes = minuteDifference(date);

    if (minutes >= -60 && minutes <= 60) {
      return formatter.format(minutes, 'minute');
    }

    const hours = hourDifference(date);

    if (hours >= -12 && hours <= 12) {
      return formatter.format(hours, 'hour');
    }
  }

  const { longDateFormatter, timeFormatter } = buildFormatters(withTime);

  const days = dayDifference(date);

  if (days >= -3 && days <= 3) {
    const datePart = `${formatter.format(days, 'day')}`;

    if (withTime) {
      return `${datePart} at ${timeFormatter.format(date)}`;
    }

    return datePart;
  }

  return longDateFormatter.format(date);
}

function minuteDifference(date: Date): number {
  return Math.round((date.getTime() - Date.now()) / MINUTE);
}

function hourDifference(date: Date): number {
  return Math.round((date.getTime() - Date.now()) / HOUR);
}

function dayDifference(date: Date): number {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const difference = date.getTime() - today.getTime();

  const days = difference / DAY;

  return Math.floor(days);
}
