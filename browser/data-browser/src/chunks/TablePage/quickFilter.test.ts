// @wc-ignore-file
import { describe, expect, it } from 'vitest';
import { Datatype, urls, type JSONValue } from '@tomic/react';
import { formatDate } from '@helpers/dates/formatDate';
import {
  cellTexts,
  filterSubjectsByQuickFilter,
  normalizeQuickFilter,
  referencedSubjects,
  rowMatchesQuickFilter,
  type QuickFilterColumn,
  type QuickFilterContext,
  type QuickFilterRow,
} from './quickFilter';

const P = (name: string) => `https://example.com/properties/${name}`;

const column = (
  name: string,
  datatype: Datatype,
  extra: Partial<QuickFilterColumn> = {},
): QuickFilterColumn => ({
  property: P(name),
  datatype,
  label: name[0].toUpperCase() + name.slice(1),
  ...extra,
});

const TITLES: Record<string, string> = {
  'https://example.com/people/ada': 'Ada Lovelace',
  'https://example.com/tags/urgent': 'urgent',
  'https://example.com/tags/later': 'later',
};

const context: QuickFilterContext = {
  titleOf: subject => TITLES[subject],
  contentLanguage: 'en',
};

const row = (values: Record<string, JSONValue>): QuickFilterRow => ({
  get: property => values[property],
});

/** Does a single cell of this column, holding this value, match the query? */
const matches = (col: QuickFilterColumn, value: JSONValue, query: string) =>
  rowMatchesQuickFilter(
    row({ [col.property]: value }),
    [col],
    normalizeQuickFilter(query),
    context,
  );

describe('quick filter matching', () => {
  it('finds text anywhere in a string, ignoring case and outer spaces', () => {
    const title = column('title', Datatype.STRING);

    expect(matches(title, 'Buy Oat Milk', 'oat')).toBe(true);
    expect(matches(title, 'Buy Oat Milk', '  MILK ')).toBe(true);
    expect(matches(title, 'Buy Oat Milk', 'cheese')).toBe(false);
  });

  it('matches every row when the query is empty', () => {
    expect(matches(column('title', Datatype.STRING), undefined, '   ')).toBe(
      true,
    );
  });

  it('reads markdown as plain text', () => {
    const notes = column('notes', Datatype.MARKDOWN);
    const value = 'Call **the plumber** about [the leak](https://x.test/1)';

    expect(matches(notes, value, 'call the plumber')).toBe(true);
    expect(matches(notes, value, 'about the leak')).toBe(true);
    expect(matches(notes, value, 'dentist')).toBe(false);
  });

  it('matches a number as shown and as typed', () => {
    const count = column('count', Datatype.INTEGER);
    const shown = new Intl.NumberFormat('default').format(1234567);

    expect(matches(count, 1234567, shown)).toBe(true);
    expect(matches(count, 1234567, '1234567')).toBe(true);
    expect(matches(count, 1234567, '999')).toBe(false);
  });

  it('matches a float with its formatting, e.g. as a percentage', () => {
    const progress = column('progress', Datatype.FLOAT, {
      numberFormatting: urls.instances.numberFormats.percentage,
    });
    const shown = cellTexts(42, progress, context)[0];

    expect(shown).toContain('%');
    expect(matches(progress, 42, shown)).toBe(true);
  });

  it('matches a date as it is displayed, not as it is stored', () => {
    const due = column('due', Datatype.DATE, {
      dateFormat: urls.instances.dateFormats.localLong,
    });
    // A civil date is local midnight of that day (#1812), whatever the zone.
    const shown = formatDate(
      urls.instances.dateFormats.localLong,
      new Date(2026, 9, 2),
      false,
    );

    expect(cellTexts('2026-10-02', due, context)).toEqual([shown]);
    expect(matches(due, '2026-10-02', shown)).toBe(true);
    // The month name is in the long format, so part of it finds the row too.
    expect(matches(due, '2026-10-02', shown.split(' ')[0])).toBe(true);
    expect(matches(due, '2026-10-02', '2026-10-02')).toBe(false);
  });

  it('uses the numeric local format for a date column without one', () => {
    const due = column('due', Datatype.DATE);
    const shown = formatDate(
      urls.instances.dateFormats.localNumeric,
      new Date(2026, 9, 2),
      false,
    );

    expect(cellTexts('2026-10-02', due, context)).toEqual([shown]);
  });

  it('matches a timestamp as displayed, with its time', () => {
    const at = column('at', Datatype.TIMESTAMP);
    const instant = new Date(2026, 0, 15, 14, 30).getTime();
    const shown = formatDate(
      urls.instances.dateFormats.localNumeric,
      new Date(instant),
      true,
    );

    expect(matches(at, instant, shown)).toBe(true);
  });

  it('reads a ticked checkbox as its column label, an unticked one as nothing', () => {
    const done = column('done', Datatype.BOOLEAN);

    expect(matches(done, true, 'done')).toBe(true);
    expect(matches(done, false, 'done')).toBe(false);
    expect(matches(done, false, 'false')).toBe(false);
  });

  it('matches a reference by its title', () => {
    const owner = column('owner', Datatype.ATOMIC_URL);

    expect(matches(owner, 'https://example.com/people/ada', 'lovelace')).toBe(
      true,
    );
    // The URL is not what the cell shows once the title is known.
    expect(matches(owner, 'https://example.com/people/ada', 'people')).toBe(
      false,
    );
  });

  it('falls back to the subject for a reference with no title yet', () => {
    const owner = column('owner', Datatype.ATOMIC_URL);

    expect(matches(owner, 'https://example.com/people/bob', 'bob')).toBe(true);
  });

  it('matches a multi-value cell by any of its items', () => {
    const tags = column('tags', Datatype.RESOURCEARRAY);
    const value = [
      'https://example.com/tags/urgent',
      'https://example.com/tags/later',
    ];

    expect(matches(tags, value, 'urgent')).toBe(true);
    expect(matches(tags, value, 'LATER')).toBe(true);
    expect(matches(tags, value, 'someday')).toBe(false);
  });

  it('reads localized text in the content language or the split language', () => {
    const name = column('name', Datatype.LOCALIZEDTEXT);
    const value = { en: 'Apple', nl: 'Appel' };

    expect(matches(name, value, 'apple')).toBe(true);
    expect(matches(name, value, 'appel')).toBe(false);
    expect(matches({ ...name, languageTag: 'nl' }, value, 'appel')).toBe(true);
  });

  it('matches a row when any one of its columns matches', () => {
    const columns = [
      column('title', Datatype.STRING),
      column('owner', Datatype.ATOMIC_URL),
    ];
    const r = row({
      [P('title')]: 'Fix the roof',
      [P('owner')]: 'https://example.com/people/ada',
    });

    expect(rowMatchesQuickFilter(r, columns, 'roof', context)).toBe(true);
    expect(rowMatchesQuickFilter(r, columns, 'ada', context)).toBe(true);
    expect(rowMatchesQuickFilter(r, columns, 'garden', context)).toBe(false);
  });
});

describe('filtering a list of rows', () => {
  const title = column('title', Datatype.STRING);
  const rows: Record<string, QuickFilterRow> = {
    a: row({ [P('title')]: 'Apples' }),
    b: row({ [P('title')]: 'Bananas' }),
    c: row({ [P('title')]: 'Pineapple' }),
  };

  it('keeps the matching rows in the order it was given', () => {
    expect(
      filterSubjectsByQuickFilter(
        ['c', 'b', 'a'],
        s => rows[s],
        [title],
        'APPLE',
        context,
      ),
    ).toEqual(['c', 'a']);
  });

  it('returns the list unchanged for an empty query', () => {
    const subjects = ['a', 'b', 'c'];

    expect(
      filterSubjectsByQuickFilter(
        subjects,
        s => rows[s],
        [title],
        ' ',
        context,
      ),
    ).toBe(subjects);
  });

  it('leaves out a row that has not loaded', () => {
    expect(
      filterSubjectsByQuickFilter(
        ['a', 'missing'],
        s => rows[s],
        [title],
        'a',
        context,
      ),
    ).toEqual(['a']);
  });
});

describe('referenced subjects', () => {
  it('collects every reference the reference columns show, once', () => {
    const columns = [
      column('title', Datatype.STRING),
      column('owner', Datatype.ATOMIC_URL),
      column('tags', Datatype.RESOURCEARRAY),
    ];

    expect(
      referencedSubjects(
        [
          row({
            [P('title')]: 'https://not-a-reference.test',
            [P('owner')]: 'https://example.com/people/ada',
            [P('tags')]: ['https://example.com/tags/urgent'],
          }),
          row({ [P('owner')]: 'https://example.com/people/ada' }),
        ],
        columns,
      ).sort(),
    ).toEqual([
      'https://example.com/people/ada',
      'https://example.com/tags/urgent',
    ]);
  });
});
