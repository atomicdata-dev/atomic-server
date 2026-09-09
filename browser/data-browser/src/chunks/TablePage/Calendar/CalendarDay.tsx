import type { CalendarOccurrence } from '@tomic/lib';
import { useResource, useTitle } from '@tomic/react';
import { styled } from 'styled-components';
import { useCallback, useRef, useState, type JSX } from 'react';
import { FaPlus } from 'react-icons/fa6';
import { IconButton } from '@components/IconButton/IconButton';
import { InputStyled } from '@components/forms/InputStyles';
import { useResourceContextMenu } from '@components/ResourceContextMenu/ResourceContextMenuContext';

interface CalendarDayProps {
  /** Local YYYY-MM-DD key of this day. */
  dayKey: string;
  dayNumber: number;
  /** Whether the day belongs to the displayed month (leading/trailing days dim). */
  inMonth: boolean;
  isToday: boolean;
  /** Row subjects whose date value falls on this day. */
  eventSubjects: string[];
  occurrences: CalendarOccurrence[];
  allDaySubjects: ReadonlySet<string>;
  readOnly: boolean;
  /** Create a row with its date preset to this day. */
  onAddItem: (dayKey: string, name: string) => void | Promise<void>;
  /** Open a row in the expanded (modal) view. */
  onOpenItem: (subject: string) => void;
}

/** One day cell of the month grid: day number, its rows, and a hover `+`. */
export function CalendarDay({
  dayKey,
  dayNumber,
  inMonth,
  isToday,
  eventSubjects,
  occurrences,
  allDaySubjects,
  readOnly,
  onAddItem,
  onOpenItem,
}: CalendarDayProps): JSX.Element {
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const submit = useCallback(() => {
    const trimmed = draft.trim();

    if (trimmed) {
      void onAddItem(dayKey, trimmed);
    }

    setDraft('');
    setAdding(false);
  }, [draft, dayKey, onAddItem]);

  const openAdder = useCallback(() => {
    setAdding(true);
    // Focus after the input mounts.
    window.setTimeout(() => inputRef.current?.focus(), 0);
  }, []);

  return (
    <Cell $inMonth={inMonth} data-testid='calendar-day' data-date={dayKey}>
      <CellHeader>
        <DayNumber $today={isToday} aria-current={isToday ? 'date' : undefined}>
          {dayNumber}
        </DayNumber>
        {!readOnly && (
          <AddIcon
            title='Add item'
            type='button'
            data-testid='calendar-day-add'
            onClick={openAdder}
          >
            <FaPlus />
          </AddIcon>
        )}
      </CellHeader>
      <EventList>
        {eventSubjects.map(subject => (
          <CalendarEvent
            key={subject}
            subject={subject}
            allDay={allDaySubjects.has(subject)}
            onOpen={onOpenItem}
          />
        ))}
        {occurrences.map(occurrence => (
          <CalendarEvent
            key={occurrence.key}
            subject={occurrence.subject}
            allDay={occurrence.allDay}
            recurring={occurrence.recurring}
            onOpen={onOpenItem}
          />
        ))}
        {adding && (
          <AddInput
            ref={inputRef}
            placeholder='New item…'
            value={draft}
            onChange={e => setDraft(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter') {
                e.preventDefault();
                submit();
              } else if (e.key === 'Escape') {
                setDraft('');
                setAdding(false);
              }
            }}
            onBlur={submit}
          />
        )}
      </EventList>
    </Cell>
  );
}

/** A row rendered as a small chip on its day; click opens, RMB = resource menu. */
function CalendarEvent({
  subject,
  onOpen,
  allDay,
  recurring = false,
}: {
  subject: string;
  allDay: boolean;
  recurring?: boolean;
  onOpen: (subject: string) => void;
}): JSX.Element {
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  const { openResourceMenu } = useResourceContextMenu();

  return (
    <EventChip
      type='button'
      data-testid='calendar-event'
      title={
        recurring
          ? `${title || subject} · Recurring meeting (opens its series or exception)`
          : title || subject
      }
      data-all-day={allDay || undefined}
      data-recurring={recurring || undefined}
      onClick={() => onOpen(subject)}
      onContextMenu={e => openResourceMenu(subject, e)}
    >
      {recurring && <span aria-label='Recurring meeting'>↻ </span>}
      {allDay && <AllDayLabel>All day</AllDayLabel>}
      {title || subject}
    </EventChip>
  );
}

const Cell = styled.div<{ $inMonth: boolean }>`
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  padding: 0.3rem;
  min-height: 0;
  background-color: ${p => (p.$inMonth ? p.theme.colors.bg : 'transparent')};
  opacity: ${p => (p.$inMonth ? 1 : 0.5)};
`;

const CellHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
`;

const DayNumber = styled.span<{ $today: boolean }>`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 1.5rem;
  height: 1.5rem;
  padding-inline: 0.2rem;
  border-radius: 50%;
  font-size: 0.85em;
  font-weight: ${p => (p.$today ? 'bold' : 'normal')};
  background-color: ${p => (p.$today ? p.theme.colors.main : 'transparent')};
  color: ${p => (p.$today ? 'white' : p.theme.colors.textLight)};
`;

const AddIcon = styled(IconButton)`
  height: 1.5rem;
  width: 1.5rem;
  opacity: 0;
  transition: opacity 0.1s ease-in-out;

  ${Cell}:hover &,
  &:focus-visible {
    opacity: 1;
  }
`;

const EventList = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  min-height: 0;
  overflow-y: auto;
`;

const EventChip = styled.button`
  border: none;
  text-align: start;
  padding: 0.15rem 0.4rem;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg1};
  color: ${p => p.theme.colors.text};
  font-size: 0.8em;
  cursor: pointer;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  flex-shrink: 0;

  &:hover {
    background-color: ${p => p.theme.colors.bg2};
  }
`;

const AddInput = styled(InputStyled)`
  flex: 0 0 auto;
  height: auto;
  min-height: 1.6rem;
  padding: 0.15rem 0.4rem;
  font-size: 0.8em;
  border: 1px solid ${p => p.theme.colors.main};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg};
`;

const AllDayLabel = styled.span`
  font-size: 0.8em;
  margin-inline-end: 0.4em;
  opacity: 0.7;
`;
