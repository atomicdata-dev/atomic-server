import { describe, expect, it } from 'vitest';
import { toShortRelativeTime } from './relativeDate';

const NOW = Date.UTC(2026, 5, 15, 12, 0, 0);
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

const ago = (ms: number) => toShortRelativeTime(new Date(NOW - ms), NOW);

describe('toShortRelativeTime', () => {
  it('uses "now" under a minute and for future dates', () => {
    expect(ago(0)).toBe('now');
    expect(ago(59_000)).toBe('now');
    expect(ago(-5 * HOUR)).toBe('now');
  });

  it.each([
    [MIN, '1m ago'],
    [59 * MIN, '59m ago'],
    [HOUR, '1h ago'],
    [23 * HOUR, '23h ago'],
    [DAY, '1d ago'],
    [6 * DAY, '6d ago'],
    [7 * DAY, '1w ago'],
    [28 * DAY, '4w ago'],
    [30 * DAY, '1mo ago'],
    [330 * DAY, '11mo ago'],
    [364 * DAY, '11mo ago'],
    [365 * DAY, '1y ago'],
    [800 * DAY, '2y ago'],
  ])('%i ms -> %s', (ms, label) => {
    expect(ago(ms)).toBe(label);
  });
});
