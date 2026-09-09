import {
  calendarRecurrenceShortname,
  type CalendarRecord,
  type CalendarOccurrence,
} from '@tomic/lib';
import {
  calendarOccurrenceBuckets,
  calendarPropertyMatches,
} from './calendarOccurrences';
import { WarningBlock } from '@components/WarningBlock';
import {
  Collection,
  Datatype,
  JSONValue,
  Resource,
  Property,
  commits,
  core,
  unknownSubject,
  useResources,
  useStore,
} from '@tomic/react';
import { useCallback, useEffect, useMemo, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaChevronLeft, FaChevronRight } from 'react-icons/fa6';
import { LoaderBlock } from '@components/Loader';
import { IconButton } from '@components/IconButton/IconButton';
import { Button } from '@components/Button';
import { ExpandedRowDialog } from '../ExpandedRowDialog';
import { useCalendarDateProp } from './useCalendarDateProp';
import { CalendarDay } from './CalendarDay';
import { calendarFields, isAllDayOnDate, nextCalendarDate } from '@tomic/lib';

interface CalendarViewProps {
  /** The Table resource; new items are created as its children. */
  tableSubject: string;
  tableClass: Resource;
  /** Every property of the class (used to find/adopt a date property). */
  allColumns: Property[];
  collection: Collection;
  ready: boolean;
  viewGroupBy: string | undefined;
  setViewGroupBy: (property: string) => void;
  readOnly: boolean;
}

/** Local YYYY-MM-DD key for a Date (NOT toISOString — that shifts timezones). */
function toDayKey(d: Date): string {
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');

  return `${d.getFullYear()}-${month}-${day}`;
}

const DATE_PREFIX_REGEX = /^\d{4}-\d{2}-\d{2}/;

/** Buckets a stored date/timestamp value into its (local) day key. */
function valueToDayKey(
  value: JSONValue | undefined,
  datatype: Datatype | undefined,
): string | undefined {
  if (datatype === Datatype.TIMESTAMP && typeof value === 'number') {
    return toDayKey(new Date(value));
  }

  if (typeof value === 'string' && DATE_PREFIX_REGEX.test(value)) {
    return value.slice(0, 10);
  }

  return undefined;
}

/** Monday-first weekday headers, localized (2024-01-01 was a Monday). */
const WEEKDAY_LABELS = Array.from({ length: 7 }, (_, i) =>
  new Date(2024, 0, 1 + i).toLocaleDateString(undefined, { weekday: 'short' }),
);

export function CalendarView({
  tableSubject,
  tableClass,
  allColumns,
  collection,
  ready,
  viewGroupBy,
  setViewGroupBy,
  readOnly,
}: CalendarViewProps): JSX.Element {
  const store = useStore();

  const { dateProp, status } = useCalendarDateProp(
    tableClass,
    allColumns,
    viewGroupBy,
    setViewGroupBy,
    !readOnly,
  );

  // The displayed month. Days outside it pad the grid to whole weeks.
  const [cursor, setCursor] = useState(() => {
    const now = new Date();

    return { year: now.getFullYear(), month: now.getMonth() };
  });

  const goToday = useCallback(() => {
    const now = new Date();
    setCursor({ year: now.getFullYear(), month: now.getMonth() });
  }, []);

  const shiftMonth = useCallback((delta: number) => {
    setCursor(prev => {
      const d = new Date(prev.year, prev.month + delta, 1);

      return { year: d.getFullYear(), month: d.getMonth() };
    });
  }, []);

  // All rows of the table, loaded up front so they can be bucketed by their
  // date value (the query index can't express a per-day filter). Re-fetched
  // when the collection identity or size changes (new/removed rows).
  const [memberSubjects, setMemberSubjects] = useState<string[]>([]);
  const totalMembers = collection.totalMembers;

  useEffect(() => {
    let cancelled = false;

    void collection
      .getAllMembers()
      .then(members => {
        if (!cancelled) {
          setMemberSubjects(members);
        }
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
    };
  }, [collection, totalMembers]);

  const rows = useResources(memberSubjects);

  // The month's grid: whole weeks (Monday-first) covering the cursor month.
  const gridDays = useMemo(() => {
    const first = new Date(cursor.year, cursor.month, 1);
    // getDay() is Sunday-first; rotate so Monday = 0.
    const offset = (first.getDay() + 6) % 7;
    const daysInMonth = new Date(cursor.year, cursor.month + 1, 0).getDate();
    const totalCells = Math.ceil((offset + daysInMonth) / 7) * 7;

    return Array.from({ length: totalCells }, (_, i) => {
      const date = new Date(cursor.year, cursor.month, i + 1 - offset);

      return {
        dayKey: toDayKey(date),
        dayNumber: date.getDate(),
        inMonth: date.getMonth() === cursor.month,
      };
    });
  }, [cursor]);

  // Imported ranges are opt-in: unrelated table date columns stay single-day.
  const calendarDate = calendarPropertyMatches(
    dateProp?.shortname,
    calendarFields.day,
  );
  const allDayProp = allColumns.find(p =>
    calendarPropertyMatches(p.shortname, calendarFields.allDay),
  );
  const endDayProp = allColumns.find(p =>
    calendarPropertyMatches(p.shortname, calendarFields.endDay),
  );
  const allDaySubjects = new Set(
    memberSubjects.filter(
      subject =>
        calendarDate &&
        allDayProp &&
        rows.get(subject)?.get(allDayProp.subject) === true,
    ),
  );

  const recurrenceProp = allColumns.find(p =>
    calendarPropertyMatches(p.shortname, calendarRecurrenceShortname),
  );
  const recurringRows = new Set<string>();
  const recurrenceRecords: CalendarRecord[] = [];

  if (calendarDate && recurrenceProp) {
    for (const subject of memberSubjects) {
      const payload = rows.get(subject)?.get(recurrenceProp.subject);

      if (
        payload &&
        typeof payload === 'object' &&
        !Array.isArray(payload) &&
        'event' in payload
      ) {
        recurringRows.add(subject);
        recurrenceRecords.push({
          ...payload,
          subject,
        } as unknown as CalendarRecord);
      }
    }
  }

  let recurrenceError = '';
  let occurrenceBuckets = new Map<string, CalendarOccurrence[]>();

  try {
    occurrenceBuckets = calendarOccurrenceBuckets(
      recurrenceRecords,
      gridDays.map(day => day.dayKey),
    );
  } catch (error) {
    recurrenceError = `Could not display recurring meetings: ${error instanceof Error ? error.message : String(error)}`;
  }

  // Bucket each row onto its day. Reactive: `useResources` re-snapshots when a
  // row's date changes, so the grid recomputes.
  const buckets = (() => {
    const map = new Map<string, string[]>();

    if (!dateProp) {
      return map;
    }

    for (const subject of memberSubjects) {
      if (recurringRows.has(subject)) continue;
      const resource = rows.get(subject);
      const value = resource?.get(dateProp.subject) as JSONValue | undefined;
      const key = valueToDayKey(value, dateProp.datatype);

      const isAllDay =
        calendarDate &&
        allDayProp &&
        resource?.get(allDayProp.subject) === true;
      const end = endDayProp && resource?.get(endDayProp.subject);

      for (const day of gridDays) {
        if (
          isAllDay && end !== undefined
            ? isAllDayOnDate(key, end, day.dayKey)
            : key === day.dayKey
        ) {
          map.set(day.dayKey, [...(map.get(day.dayKey) ?? []), subject]);
        }
      }
    }

    return map;
  })();

  const todayKey = toDayKey(new Date());

  const monthLabel = new Date(cursor.year, cursor.month, 1).toLocaleDateString(
    undefined,
    { month: 'long', year: 'numeric' },
  );

  // Open an item in the same modal the table's row-expand uses, rather than
  // navigating away to the full resource page.
  const [expandedSubject, setExpandedSubject] = useState<string>();
  const [showExpanded, setShowExpanded] = useState(false);

  const handleOpenItem = useCallback((subject: string) => {
    setExpandedSubject(subject);
    setShowExpanded(true);
  }, []);

  // Create a new item already placed on a day: a row of the table's class with
  // its date property preset. `createdAt` is required for it to appear in the
  // table. Timestamps are set to local noon so timezone shifts can't flip days.
  const handleAddItem = async (dayKey: string, name: string) => {
    const trimmed = name.trim();

    if (!trimmed || !dateProp) {
      return;
    }

    const propVals: Record<string, JSONValue> = {
      [core.properties.name]: trimmed,
      [commits.properties.createdAt]: Date.now(),
      [dateProp.subject]:
        dateProp.datatype === Datatype.TIMESTAMP
          ? new Date(`${dayKey}T12:00:00`).getTime()
          : dayKey,
    };

    if (calendarDate && allDayProp && endDayProp) {
      propVals[allDayProp.subject] = true;
      propVals[endDayProp.subject] = nextCalendarDate(dayKey);
    }

    const row = await store.newResource({
      parent: tableSubject,
      isA: tableClass.subject,
      propVals,
    });
    await row.save();
    store.notifyResourceManuallyCreated(row);
  };

  if (status === 'creating' || (!ready && memberSubjects.length === 0)) {
    return (
      <Center>
        <LoaderBlock />
      </Center>
    );
  }

  if (status === 'resolving') {
    return <Center>Setting up the calendar…</Center>;
  }

  return (
    <>
      {recurrenceError && <WarningBlock>{recurrenceError}</WarningBlock>}
      <CalendarWrapper data-testid='calendar-view'>
        <Toolbar>
          <MonthLabel>{monthLabel}</MonthLabel>
          <Nav>
            <NavIcon
              title='Previous month'
              type='button'
              onClick={() => shiftMonth(-1)}
            >
              <FaChevronLeft />
            </NavIcon>
            <Button subtle onClick={goToday}>
              Today
            </Button>
            <NavIcon
              title='Next month'
              type='button'
              onClick={() => shiftMonth(1)}
            >
              <FaChevronRight />
            </NavIcon>
          </Nav>
        </Toolbar>
        <WeekdayRow>
          {WEEKDAY_LABELS.map(label => (
            <Weekday key={label}>{label}</Weekday>
          ))}
        </WeekdayRow>
        <Grid $weeks={gridDays.length / 7}>
          {gridDays.map(day => (
            <CalendarDay
              key={day.dayKey}
              dayKey={day.dayKey}
              dayNumber={day.dayNumber}
              inMonth={day.inMonth}
              isToday={day.dayKey === todayKey}
              eventSubjects={buckets.get(day.dayKey) ?? []}
              occurrences={occurrenceBuckets.get(day.dayKey) ?? []}
              allDaySubjects={allDaySubjects}
              readOnly={readOnly}
              onAddItem={handleAddItem}
              onOpenItem={handleOpenItem}
            />
          ))}
        </Grid>
      </CalendarWrapper>
      <ExpandedRowDialog
        subject={expandedSubject ?? unknownSubject}
        open={showExpanded}
        bindOpen={setShowExpanded}
      />
    </>
  );
}

const CalendarWrapper = styled.div`
  display: flex;
  flex-direction: column;
  padding-block: 0.5rem;
  /* Fill the viewport below the title + view tabs, capped so a tall calendar
   * still leaves the page chrome visible. Mirrors the kanban Board's model. */
  height: min(80vh, calc(100dvh - 13rem));
  min-height: 24rem;
`;

const Toolbar = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  padding-bottom: 0.5rem;
  flex-shrink: 0;
`;

const MonthLabel = styled.span`
  font-weight: bold;
  font-size: 1.1em;
  text-transform: capitalize;
`;

const Nav = styled.div`
  display: flex;
  align-items: center;
  gap: 0.25rem;
`;

const NavIcon = styled(IconButton)`
  height: 1.85rem;
  width: 1.85rem;
`;

const WeekdayRow = styled.div`
  display: grid;
  grid-template-columns: repeat(7, 1fr);
  gap: 1px;
  padding-inline: 1px;
  flex-shrink: 0;
`;

const Weekday = styled.span`
  padding: 0.25rem 0.3rem;
  font-size: 0.8em;
  color: ${p => p.theme.colors.textLight};
  text-transform: capitalize;
`;

const Grid = styled.div<{ $weeks: number }>`
  display: grid;
  grid-template-columns: repeat(7, 1fr);
  grid-template-rows: repeat(${p => p.$weeks}, minmax(5rem, 1fr));
  gap: 1px;
  /* The gap + this background paints the hairline grid between the cells. */
  background-color: ${p => p.theme.colors.bg2};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  overflow: hidden;
  flex: 1;
  min-height: 0;
`;

const Center = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 2rem;
  color: ${p => p.theme.colors.textLight};
`;
