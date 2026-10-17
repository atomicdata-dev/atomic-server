import {
  JSONValue,
  Property,
  Resource,
  commits,
  core,
  useResource,
  useStore,
  useValue,
  type Store,
  type Collection,
} from '@tomic/react';
import { useCallback, useMemo, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaPlay, FaStop, FaRotateRight } from 'react-icons/fa6';
import { IconButton } from '@components/IconButton/IconButton';
import type { TableColumn } from '../useTableColumns';
import { readInstant, type DerivedColumnSpec } from '../derivedColumns';
import { useTimerProps, type TimerPropsStatus } from './useTimerProps';

/**
 * Stops every entry that is currently running. Resolved on demand from the
 * collection rather than kept in render state: the grid is virtualised, so the
 * running entry may not be among the rendered rows — and loading every row just
 * to know that would reintroduce the unbounded fetch this view exists to avoid.
 */
async function stopAllRunning(
  store: Store,
  collection: Collection,
  startProp: string,
  endProp: string,
  except?: string,
): Promise<void> {
  const members = await collection.getAllMembers();
  const stamp = Date.now();

  for (const subject of members) {
    if (subject === except) {
      continue;
    }

    const row = store.getResourceLoading(subject);

    const values = {
      [startProp]: row.get(startProp) as JSONValue | undefined,
      [endProp]: row.get(endProp) as JSONValue | undefined,
    };

    if (
      readInstant(values, startProp) !== undefined &&
      readInstant(values, endProp) === undefined
    ) {
      await row.set(endProp, stamp, false);
      await row.save();
    }
  }
}

export interface UseTimerColumnsResult {
  /** Virtual columns to append to the grid; empty until the props resolve. */
  columns: TableColumn[];
  /**
   * The Duration column, as a derived-column spec — the timer's fallback for a
   * View that configures none of its own (one added from the view menu, rather
   * than built from the Time tracker template). Nothing here is timer-specific:
   * a duration is `elapsed` over the two timestamps the view already knows.
   */
  derivedColumns: DerivedColumnSpec[];
  status: TimerPropsStatus;
  startProp: Property | undefined;
  endProp: Property | undefined;
}

/**
 * The timer's contribution to the table: a Start/Stop action column as a
 * virtual column, plus its Duration as a derived-column spec. Everything else —
 * editing, sorting, resizing, keyboard navigation, virtualisation — is the
 * table's.
 */
export function useTimerColumns(
  tableSubject: string,
  tableClass: Resource,
  allColumns: Property[],
  collection: Collection,
  viewGroupBy: string | undefined,
  setViewGroupBy: (property: string) => void,
  viewEndProp: string | undefined,
  setViewEndProp: (property: string) => void,
  exclusive: boolean,
  readOnly: boolean,
  /** False for every non-timer view; keeps this entirely inert there. */
  enabled: boolean,
  /** Tells the grid its member count grew, so a new entry actually renders. */
  onEntryCreated: () => void,
): UseTimerColumnsResult {
  const store = useStore();
  const { startProp, endProp, status } = useTimerProps(
    tableClass,
    allColumns,
    viewGroupBy,
    setViewGroupBy,
    viewEndProp,
    setViewEndProp,
    !readOnly,
    enabled,
  );

  const startSubject = startProp?.subject;
  const endSubject = endProp?.subject;

  const handleStart = useCallback(
    (subject: string) => {
      void (async () => {
        if (!startSubject || !endSubject) {
          return;
        }

        if (exclusive) {
          await stopAllRunning(
            store,
            collection,
            startSubject,
            endSubject,
            subject,
          );
        }

        const row = store.getResourceLoading(subject);
        await row.set(startSubject, Date.now(), false);
        // A restarted entry must not keep its old end, or it reads as finished
        // the moment it starts.
        row.remove(endSubject);
        await row.save();
      })().catch(() => undefined);
    },
    [store, collection, startSubject, endSubject, exclusive],
  );

  /**
   * "Start again" copies the entry into a new one that runs from now. It must
   * NOT restart the original: that would overwrite its start and clear its end,
   * destroying the record of the time already logged.
   */
  const handleResume = useCallback(
    (subject: string) => {
      void (async () => {
        if (!startSubject || !endSubject) {
          return;
        }

        const source = store.getResourceLoading(subject);

        const propVals: Record<string, JSONValue> = {
          [core.properties.name]:
            (source.get(core.properties.name) as string | undefined) ??
            'Untitled entry',
          // Required for the row to show up in the table's collection.
          [commits.properties.createdAt]: Date.now(),
          [startSubject]: Date.now(),
        };

        // Carry the rest of the row over — restarting "Borst voeden / spelen"
        // should still be on the "spelen" project. The timestamps are set
        // above, so they're skipped here.
        for (const column of allColumns) {
          if (
            column.subject === startSubject ||
            column.subject === endSubject ||
            column.subject === core.properties.name
          ) {
            continue;
          }

          const value = source.get(column.subject);

          if (value !== undefined) {
            propVals[column.subject] = value as JSONValue;
          }
        }

        if (exclusive) {
          try {
            await stopAllRunning(store, collection, startSubject, endSubject);
          } catch {
            // Losing the auto-stop must not stop the new entry — see below.
          }
        }

        const row = await store.newResource({
          parent: tableSubject,
          isA: tableClass.subject,
          propVals,
        });
        await row.save();
        store.notifyResourceManuallyCreated(row);
        onEntryCreated();
      })().catch(() => undefined);
    },
    [
      store,
      collection,
      startSubject,
      endSubject,
      exclusive,
      allColumns,
      tableSubject,
      tableClass,
      onEntryCreated,
    ],
  );

  const handleStop = useCallback(
    (subject: string) => {
      void (async () => {
        if (!endSubject) {
          return;
        }

        const row = store.getResourceLoading(subject);
        await row.set(endSubject, Date.now(), false);
        await row.save();
      })().catch(() => undefined);
    },
    [store, endSubject],
  );

  return useMemo(() => {
    if (!startSubject || !endSubject) {
      return { columns: [], derivedColumns: [], status, startProp, endProp };
    }

    const ActionCell = ({ subject }: { subject: string }): JSX.Element => (
      <TimerActionCell
        subject={subject}
        startProp={startSubject}
        endProp={endSubject}
        readOnly={readOnly}
        onStart={handleStart}
        onStop={handleStop}
        onResume={handleResume}
      />
    );

    return {
      columns: [
        {
          key: 'timer-action',
          virtual: { label: 'Timer', width: 70, Cell: ActionCell },
        },
      ],
      derivedColumns: [
        {
          id: 'duration',
          label: 'Duration',
          kind: 'elapsed' as const,
          args: { from: startSubject, until: endSubject },
          width: 130,
        },
      ],
      status,
      startProp,
      endProp,
    };
  }, [
    startSubject,
    endSubject,
    status,
    startProp,
    endProp,
    readOnly,
    handleStart,
    handleStop,
    handleResume,
  ]);
}

function TimerActionCell({
  subject,
  startProp,
  endProp,
  readOnly,
  onStart,
  onStop,
  onResume,
}: {
  subject: string;
  startProp: string;
  endProp: string;
  readOnly: boolean;
  onStart: (subject: string) => void;
  onStop: (subject: string) => void;
  onResume: (subject: string) => void;
}): JSX.Element | null {
  const resource = useResource(subject);
  // Subscribing reads, not `resource.get(...)`: a render-time read is memoized by
  // the React Compiler on the resource proxy's identity, which never changes. See
  // `useDerivedColumns`.
  const [startValue] = useValue(resource, startProp);
  const [endValue] = useValue(resource, endProp);
  const start = readInstant({ [startProp]: startValue }, startProp);
  const end = readInstant({ [endProp]: endValue }, endProp);
  const running = start !== undefined && end === undefined;

  if (readOnly) {
    return null;
  }

  if (running) {
    return (
      <Actions data-running='true' data-testid='timer-cell-action'>
        <StopButton
          title='Stop'
          type='button'
          data-testid='timer-stop'
          onClick={() => onStop(subject)}
        >
          <FaStop />
        </StopButton>
      </Actions>
    );
  }

  return (
    <Actions data-running='false' data-testid='timer-cell-action'>
      <IconButton
        title={start === undefined ? 'Start' : 'Start again'}
        type='button'
        data-testid={start === undefined ? 'timer-start' : 'timer-resume'}
        onClick={() =>
          start === undefined ? onStart(subject) : onResume(subject)
        }
      >
        {start === undefined ? <FaPlay /> : <FaRotateRight />}
      </IconButton>
    </Actions>
  );
}

const Actions = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
`;

const StopButton = styled(IconButton)`
  color: ${p => p.theme.colors.alert};
`;
