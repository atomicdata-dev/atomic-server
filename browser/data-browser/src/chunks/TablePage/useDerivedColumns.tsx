import {
  ResourceEvents,
  useResource,
  useStore,
  type JSONValue,
} from '@tomic/react';
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
  type JSX,
} from 'react';
import { styled } from 'styled-components';
import type { TableColumn } from './useTableColumns';
import {
  DEFAULT_DERIVED_WIDTH,
  computeDerived,
  formatDerivedValue,
  isLive,
  specProperties,
  type DerivedColumnSpec,
} from './derivedColumns';
import { useFormulaReady } from './formulaEngine';

/**
 * One shared 1s ticker for every live cell on screen, rather than an interval
 * each. It only runs while something is subscribed, so a table whose derived
 * columns are all settled ticks zero times.
 */
const subscribers = new Set<(now: number) => void>();
let intervalId: number | undefined;

function subscribeToTick(fn: (now: number) => void): () => void {
  subscribers.add(fn);

  if (intervalId === undefined) {
    intervalId = window.setInterval(() => {
      const now = Date.now();

      for (const sub of subscribers) {
        sub(now);
      }
    }, 1000);
  }

  return () => {
    subscribers.delete(fn);

    if (subscribers.size === 0 && intervalId !== undefined) {
      window.clearInterval(intervalId);
      intervalId = undefined;
    }
  };
}

/** `Date.now()`, refreshed every second while `active`. */
function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!active) {
      return;
    }

    setNow(Date.now());

    return subscribeToTick(setNow);
  }, [active]);

  return now;
}

/**
 * Turns a View's derived-column specs into grid columns, using the `virtual`
 * seam — so the editor stack (`FancyTable<T>`, `useCellSizes<T>`) never learns
 * that computed columns exist, and every table feature keeps working around
 * them.
 */
export function useDerivedColumns(specs: DerivedColumnSpec[]): TableColumn[] {
  // The specs are parsed out of the View's JSON, so their identity churns on
  // every render. Keying on their serialized shape keeps both the columns and
  // the `Cell` component bound to each spec stable — otherwise every derived
  // cell would remount once a render.
  const specsKey = JSON.stringify(specs);

  return useMemo(() => {
    const stable = JSON.parse(specsKey) as DerivedColumnSpec[];

    return stable.map((spec): TableColumn => {
      const Cell = ({ subject }: { subject: string }): JSX.Element => (
        <DerivedCell subject={subject} spec={spec} />
      );

      return {
        key: `derived:${spec.id}`,
        derived: spec,
        virtual: {
          label: spec.label,
          width: spec.width ?? DEFAULT_DERIVED_WIDTH,
          Cell,
        },
      };
    });
  }, [specsKey]);
}

/**
 * The current values of some of a row's properties, re-read whenever the row
 * changes — as many as the formula names, in one hook call, so the number of
 * hooks never depends on the formula (the rules of hooks).
 *
 * Reading `resource.get(...)` during render instead made the React Compiler
 * memoize the result on the resource proxy's identity, which never changes
 * because the store mutates resources in place: a computed column showed what it
 * computed at mount until the page was reloaded. The snapshot is therefore read
 * inside `useSyncExternalStore`, as a string, so equal values are equal.
 */
function useRowValues(
  subject: string,
  properties: string[],
): Record<string, JSONValue | undefined> {
  const store = useStore();
  const resource = useResource(subject);
  const stable = resource.stable;
  const subscribe = useCallback(
    (notify: () => void) => {
      const unsubscribeStore = store.subscribe(subject, () => notify());
      const unsubscribeLocal = stable.on(ResourceEvents.LocalChange, notify);

      return () => {
        unsubscribeStore();
        unsubscribeLocal();
      };
    },
    [store, subject, stable],
  );
  const read = () =>
    JSON.stringify(properties.map(property => resource.get(property) ?? null));
  const json = useSyncExternalStore(subscribe, read, read);

  return useMemo(() => {
    const values = JSON.parse(json) as JSONValue[];

    return Object.fromEntries(
      properties.map((property, i) => [property, values[i] ?? undefined]),
    );
  }, [json]);
}

function DerivedCell({
  subject,
  spec,
}: {
  subject: string;
  spec: DerivedColumnSpec;
}): JSX.Element {
  const values = useRowValues(subject, specProperties(spec));
  // The evaluator loads lazily: until it has, a cell is empty rather than wrong.
  useFormulaReady();

  // A running duration ticks; a finished one reads the same at any instant.
  const live =
    isLive(spec) &&
    computeDerived(spec, values, 0) !== computeDerived(spec, values, 1);
  const now = useNow(live);
  const value = computeDerived(spec, values, now);

  return (
    <Value $live={live} data-testid={`derived-${spec.id}`}>
      {value === undefined ? '' : formatDerivedValue(spec, value)}
    </Value>
  );
}

// A div, not a span: the grid row draws its cell borders with `& > div`, so a
// span would render without any.
const Value = styled.div<{ $live: boolean }>`
  display: flex;
  align-items: center;
  padding-inline: var(--table-inner-padding);
  font-variant-numeric: tabular-nums;
  font-weight: ${p => (p.$live ? 'bold' : 'normal')};
  color: ${p =>
    p.$live ? p.theme.colors.mainSelectedFg : p.theme.colors.text};
`;
