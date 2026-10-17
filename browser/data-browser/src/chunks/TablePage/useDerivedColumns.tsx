import { useResource, useValue } from '@tomic/react';
import { useEffect, useMemo, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import type { TableColumn } from './useTableColumns';
import {
  DERIVED_COLUMN_GENERATORS,
  argProperties,
  type ArgValues,
  type DerivedColumnSpec,
} from './derivedColumns';

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
      const generator = DERIVED_COLUMN_GENERATORS[spec.kind];

      const Cell = ({ subject }: { subject: string }): JSX.Element => (
        <DerivedCell subject={subject} spec={spec} />
      );

      return {
        key: `derived:${spec.id}`,
        derived: spec,
        virtual: {
          label: spec.label,
          width: spec.width ?? generator.width,
          Cell,
        },
      };
    });
  }, [specsKey]);
}

function DerivedCell({
  subject,
  spec,
}: {
  subject: string;
  spec: DerivedColumnSpec;
}): JSX.Element {
  const resource = useResource(subject);
  const generator = DERIVED_COLUMN_GENERATORS[spec.kind];

  // Subscribing reads of exactly the properties this column derives from.
  //
  // Two calls, unconditionally, because no generator declares more than
  // `MAX_DERIVED_ARGS` arguments (`derivedColumns.test.ts` holds that, so a third
  // one fails there rather than here) — and a *fixed* number
  // of hook calls is what the rules of hooks require. Looping over the spec's
  // arguments instead is a violation the React Compiler is free to break, and
  // does.
  //
  // These values, not the resource, are what `compute` is a function of. Reading
  // `resource.get(...)` during render made the Compiler memoize the result on the
  // proxy's identity — which never changes, because the store mutates resources
  // in place — so a computed column showed whatever it computed at mount until
  // the page was reloaded.
  const [firstProperty = '', secondProperty = ''] = argProperties(spec);
  const [firstValue] = useValue(resource, firstProperty);
  const [secondValue] = useValue(resource, secondProperty);

  const values: ArgValues = useMemo(
    () => ({ [firstProperty]: firstValue, [secondProperty]: secondValue }),
    [firstProperty, firstValue, secondProperty, secondValue],
  );

  const live = generator.live?.(values, spec.args) ?? false;
  const now = useNow(live);
  const value = generator.compute(values, spec.args, now);

  return (
    <Value $live={live} data-testid={`derived-${spec.id}`}>
      {value === undefined ? '' : generator.format(value)}
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
