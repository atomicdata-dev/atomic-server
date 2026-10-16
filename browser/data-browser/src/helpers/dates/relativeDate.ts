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

const shortFormatter = new Intl.RelativeTimeFormat(undefined, {
  numeric: 'always',
  style: 'narrow',
});
const nowFormatter = new Intl.RelativeTimeFormat(undefined, {
  numeric: 'auto',
  style: 'narrow',
});

/**
 * A very short relative time for dense lists: "now", "5m ago", "3h ago",
 * "2d ago", "3w ago", "4mo ago", "2y ago" (localised by the browser's
 * `Intl.RelativeTimeFormat`, narrow style). Future dates clamp to "now".
 */
export function toShortRelativeTime(date: Date, now = Date.now()): string {
  const ms = Math.max(0, now - date.getTime());
  const minutes = Math.floor(ms / MINUTE);
  const hours = Math.floor(ms / HOUR);
  const days = Math.floor(ms / DAY);

  let value: number;
  let unit: Intl.RelativeTimeFormatUnit;

  if (minutes < 1) {
    return nowFormatter.format(0, 'second');
  } else if (hours < 1) {
    [value, unit] = [minutes, 'minute'];
  } else if (days < 1) {
    [value, unit] = [hours, 'hour'];
  } else if (days < 7) {
    [value, unit] = [days, 'day'];
  } else if (days < 30) {
    [value, unit] = [Math.floor(days / 7), 'week'];
  } else if (days < 365) {
    [value, unit] = [Math.min(11, Math.floor(days / 30)), 'month'];
  } else {
    [value, unit] = [Math.floor(days / 365), 'year'];
  }

  return shortFormatter.format(-value, unit);
}
