// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { Datatype, urls, type Property } from '@tomic/react';
import ValueComp from '../../components/ValueComp';
import {
  formatAggregateValue,
  formatGroupKey,
} from '../../chunks/TablePage/tableAggregates';
import { toDisplayData } from '../../chunks/TablePage/EditorCells/DateCell';
import { formatDiffDate } from '../../chunks/ResourceDiff/ResourceDiff';
import {
  calendarDateToLocalDate,
  formatCalendarDate,
  localCalendarDate,
} from './calendarDate';

// A civil date has no zone, so it must read the same everywhere. Run each case
// east and west of Greenwich: east is where `new Date('2026-10-02')` grows a
// 02:00 time, west is where it becomes the day before.
const ZONES = ['Europe/Amsterdam', 'America/New_York'];

const DAY = urls.instances.dateFormats.localNumeric;
const DATE_PROP = { datatype: Datatype.DATE } as unknown as Property;

/** How this zone and locale write 2 October 2026, built without parsing. */
const expected = (options?: Intl.DateTimeFormatOptions) =>
  new Date(2026, 9, 2).toLocaleDateString(undefined, options);

afterEach(cleanup);

for (const zone of ZONES) {
  describe(`a date value in ${zone}`, () => {
    const original = process.env.TZ;

    beforeAll(() => {
      process.env.TZ = zone;
    });

    afterAll(() => {
      process.env.TZ = original;
    });

    it('runs in a zone that is not UTC', () => {
      expect(new Date(Date.UTC(2026, 9, 2)).getHours()).not.toBe(0);
    });

    it('parses to local midnight of the same day', () => {
      const date = calendarDateToLocalDate('2026-10-02')!;

      expect([date.getFullYear(), date.getMonth(), date.getDate()]).toEqual([
        2026, 9, 2,
      ]);
      expect(date.getHours()).toBe(0);
      expect(calendarDateToLocalDate('2026-02-30')).toBeUndefined();
      expect(formatCalendarDate('not a date')).toBe('not a date');
    });

    it('shows only the date in the row dialog and on the resource page', () => {
      const { container } = render(
        <ValueComp value='2026-10-02' datatype={Datatype.DATE} />,
      );
      const time = container.querySelector('time')!;

      expect(time.textContent).toBe(expected());
      expect(time.textContent).not.toMatch(/\d:\d\d/);
      expect(time.getAttribute('dateTime')).toBe('2026-10-02');
    });

    it('shows the same day in a table cell', () => {
      expect(toDisplayData('2026-10-02', DAY)).toBe(
        new Intl.DateTimeFormat(undefined, {
          day: 'numeric',
          month: 'numeric',
          year: 'numeric',
        }).format(new Date(2026, 9, 2)),
      );
    });

    it('shows the same day as the earliest of a date column', () => {
      expect(formatAggregateValue(Date.UTC(2026, 9, 2), 'min', DATE_PROP)).toBe(
        expected(),
      );
    });

    it('shows the same day as a group heading', () => {
      expect(formatGroupKey('2026-10-02', 'day')).toBe(
        expected({
          weekday: 'short',
          day: 'numeric',
          month: 'short',
          year: 'numeric',
        }),
      );
      expect(formatGroupKey('2026-10', 'month')).toBe(
        new Date(2026, 9, 1).toLocaleDateString(undefined, {
          month: 'long',
          year: 'numeric',
        }),
      );
    });

    it('shows the same day, without a time, in the history diff', () => {
      const shown = formatDiffDate('2026-10-02', Datatype.DATE);

      expect(shown).toBe(
        new Intl.DateTimeFormat('default', { dateStyle: 'medium' }).format(
          new Date(2026, 9, 2),
        ),
      );
    });
  });
}

describe('localCalendarDate', () => {
  it('names the local day, also just after local midnight', () => {
    // 00:24 on 9 October in whatever zone this runs in: in a zone ahead of UTC
    // the UTC day is still the 8th, which is what a "stamp today" button wrote.
    const justAfterMidnight = new Date(2026, 9, 9, 0, 24);

    expect(localCalendarDate(justAfterMidnight)).toBe('2026-10-09');
    expect(
      calendarDateToLocalDate(localCalendarDate(justAfterMidnight)),
    ).toEqual(new Date(2026, 9, 9));
  });

  it('pads short years, months and days', () => {
    expect(localCalendarDate(new Date(2026, 0, 5, 23, 59))).toBe('2026-01-05');
  });
});
