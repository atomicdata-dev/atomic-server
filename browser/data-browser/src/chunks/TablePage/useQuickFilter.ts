import {
  core,
  server,
  urls,
  dataBrowser,
  useResources,
  type AggregateOutcome,
  type Aggregation,
  type Collection,
  type Datatype,
  type JSONValue,
  type Property,
} from '@tomic/react';
import { useEffect, useMemo, useState } from 'react';
import { useSettings } from '../../helpers/AppSettings';
import { usePropertyTitles } from './helpers/usePropertyTitles';
import { aggregateRows } from './tableAggregates';
import {
  filterSubjectsBySearchText,
  normalizeQuickFilter,
  referencedSubjects,
  rowSearchText,
  type QuickFilterColumn,
  type QuickFilterContext,
} from './quickFilter';

/** A column the quick filter searches: a property, split by language or not. */
export interface QuickFilterSource {
  property: Property;
  languageTag?: string;
}

export interface QuickFilterResult {
  /** True while there is text to filter by. */
  active: boolean;
  /**
   * What the view should render: the view's own collection when inactive, the
   * matching rows (in the collection's order) when active.
   */
  collection: Collection;
  /** The matching subjects, in order. Empty while inactive. */
  matches: string[];
  /** True while the rows to search through are still being fetched. */
  loading: boolean;
}

const EMPTY: string[] = [];

/**
 * Narrows a view's rows to the ones where any of `columns` shows `query` — see
 * `quickFilter.ts` for what "shows" means per datatype.
 *
 * The collection is the view's own query, column filters and sort included, so
 * the quick filter combines with both for free: it only ever removes rows from
 * what the view would otherwise show, and keeps their order. It walks every page
 * of that collection (the grid itself fetches 30 rows at a time), so it finds a
 * row you have not scrolled to yet; nothing is fetched while the field is empty.
 */
export function useQuickFilter(
  collection: Collection,
  columns: QuickFilterSource[],
  query: string,
): QuickFilterResult {
  const normalized = normalizeQuickFilter(query);
  const active = normalized !== '';
  const { contentLanguage } = useSettings();

  // Every member, fetched only while filtering. Tagged with the collection it
  // came from, so a stale list is never searched as if it answered a new query.
  const [members, setMembers] = useState<{
    from: Collection;
    subjects: string[];
  }>();
  const totalMembers = collection.totalMembers;

  useEffect(() => {
    if (!active) {
      return;
    }

    let cancelled = false;

    collection
      .getAllMembers()
      .then(subjects => {
        if (!cancelled) {
          setMembers({ from: collection, subjects });
        }
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
    };
  }, [active, collection, totalMembers]);

  const memberSubjects =
    active && members?.from === collection ? members.subjects : EMPTY;
  const rows = useResources(memberSubjects);

  // Formatting constraints live on the Property resources.
  const properties = useMemo(() => {
    const seen = new Map<string, Property>();

    for (const { property } of columns) {
      seen.set(property.subject, property);
    }

    return [...seen.values()];
  }, [columns]);
  const propertySubjects = useMemo(
    () => (active ? properties.map(p => p.subject) : EMPTY),
    [active, properties],
  );
  const propertyResources = useResources(propertySubjects);
  const labels = usePropertyTitles(properties);

  const quickColumns = useMemo(
    (): QuickFilterColumn[] =>
      columns.map(({ property, languageTag }) => {
        const resource = propertyResources.get(property.subject);
        const read = <T>(prop: string) => resource?.get(prop) as T | undefined;

        return {
          property: property.subject,
          datatype: property.datatype as Datatype,
          label: labels.get(property.subject) ?? property.shortname,
          languageTag,
          dateFormat: read<string>(urls.properties.constraints.dateFormat),
          numberFormatting: read<string>(
            urls.properties.constraints.numberFormatting,
          ),
          decimalPlaces: read<number>(
            urls.properties.constraints.decimalPlaces,
          ),
          currency: read<string>(dataBrowser.properties.currency),
        };
      }),
    [columns, propertyResources, labels],
  );

  // A reference is searched by its title, so the resources it points at have
  // to be loaded too. Keyed on content: `rows` changes on every edit, and a new
  // array would resubscribe every reference.
  const referenceKey = useMemo(
    () => referencedSubjects(rows.values(), quickColumns).join('\n'),
    [rows, quickColumns],
  );
  const references = useMemo(
    () => (referenceKey === '' ? EMPTY : referenceKey.split('\n')),
    [referenceKey],
  );
  const referenceResources = useResources(references);

  const context = useMemo(
    (): QuickFilterContext => ({
      contentLanguage,
      titleOf: subject => {
        const resource = referenceResources.get(subject);

        if (!resource || resource.loading || resource.error) {
          return undefined;
        }

        return (resource.get(core.properties.name) ??
          resource.get(core.properties.shortname) ??
          resource.get(server.properties.filename)) as string | undefined;
      },
    }),
    [contentLanguage, referenceResources],
  );

  // What each row shows, rebuilt when a row, a column or a title changes — not
  // on every keystroke.
  const searchTexts = useMemo(() => {
    const texts = new Map<string, string>();

    for (const [subject, row] of rows) {
      if (!row.loading && !row.error) {
        texts.set(subject, rowSearchText(row, quickColumns, context));
      }
    }

    return texts;
  }, [rows, quickColumns, context]);

  const matchKey = useMemo(
    () =>
      active
        ? filterSubjectsBySearchText(
            memberSubjects,
            subject => searchTexts.get(subject),
            normalized,
          ).join('\n')
        : '',
    [active, memberSubjects, searchTexts, normalized],
  );

  // Stable while the same rows match, so an edit that doesn't change the result
  // doesn't make the views re-resolve their rows.
  const matches = useMemo(
    () => (matchKey === '' ? EMPTY : matchKey.split('\n')),
    [matchKey],
  );

  const filtered = useMemo(() => subjectListCollection(matches), [matches]);

  return {
    active,
    collection: active ? filtered : collection,
    matches: active ? matches : EMPTY,
    loading: active && members?.from !== collection,
  };
}

/**
 * The totals to show under a quick-filtered view: over the rows that match,
 * computed here since the store only knows the view's own query. While the
 * field is empty, the store's `outcomes` (over every row the view matches)
 * pass through unchanged — so the footer's row count and its totals always
 * describe the same rows.
 */
export function useQuickFilterAggregates(
  quickFilter: Pick<QuickFilterResult, 'active' | 'matches'>,
  aggregation: Aggregation | undefined,
  outcomes: AggregateOutcome[],
): AggregateOutcome[] {
  const rows = useResources(
    quickFilter.active && aggregation ? quickFilter.matches : EMPTY,
  );

  return useMemo(() => {
    if (!quickFilter.active || !aggregation) {
      return outcomes;
    }

    const readers = quickFilter.matches.flatMap(subject => {
      const row = rows.get(subject);

      return row && !row.error
        ? [(property: string) => row.get(property) as JSONValue | undefined]
        : [];
    });

    return aggregateRows(readers, aggregation);
  }, [quickFilter.active, quickFilter.matches, aggregation, outcomes, rows]);
}

/**
 * A fixed list of subjects, in the shape the views read a `Collection` in: by
 * index (the grid, its copy/paste/delete and presence helpers), and whole (the
 * board, the issue list, the calendar). Those are the only parts of a
 * `Collection` a row view reads, which is what lets the quick filter narrow
 * every view kind without each of them knowing about it.
 */
export function subjectListCollection(subjects: string[]): Collection {
  const list = {
    totalMembers: subjects.length,
    getMemberWithIndex: async (index: number) => {
      if (index < 0 || index >= subjects.length) {
        throw new Error('Index out of bounds');
      }

      return subjects[index];
    },
    getAllMembers: async () => [...subjects],
    async *[Symbol.asyncIterator]() {
      yield* subjects;
    },
  };

  return list as unknown as Collection;
}
