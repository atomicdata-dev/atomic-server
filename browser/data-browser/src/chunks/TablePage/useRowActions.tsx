import { useResource, useStore, useValue, type Property } from '@tomic/react';
import { useMemo, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaCheck } from 'react-icons/fa6';
import { ghostButtonStyles } from '@components/Button';
import type { TableColumn } from './useTableColumns';
import { useIsUnsavedDraft } from './draftRow';
import {
  ROW_ACTION_GENERATORS,
  applyRowAction,
  isRowActionComplete,
  rowActionKey,
  type RowActionSpec,
} from './rowActions';

/**
 * Turns a View's configured row actions into grid columns, through the same
 * `virtual` seam computed columns use — so the editor stack never learns that
 * action columns exist and every table feature keeps working around them.
 */
export function useRowActions(
  specs: RowActionSpec[],
  /** The row class's properties, for the datatype an action writes. */
  classProperties: Property[],
  /** No buttons at all for a viewer who cannot write: an action that is going to
   *  fail is worse than no action. */
  readOnly: boolean,
): TableColumn[] {
  // Serialized deps: the specs are parsed out of the View's JSON, so their
  // identity churns every render, and a fresh `Cell` component per render would
  // remount every button once a second.
  const specsKey = JSON.stringify(specs);
  const propertyMap = useMemo(
    () => new Map(classProperties.map(p => [p.subject, p])),
    [classProperties],
  );

  return useMemo(() => {
    if (readOnly) {
      return [];
    }

    const parsed = JSON.parse(specsKey) as RowActionSpec[];

    return parsed.map((spec): TableColumn => {
      const property = propertyMap.get(spec.property);

      const Cell = ({ subject }: { subject: string }): JSX.Element | null => (
        <RowActionCell subject={subject} spec={spec} property={property} />
      );

      return {
        key: rowActionKey(spec.id),
        virtual: {
          label: spec.label,
          width: ROW_ACTION_GENERATORS[spec.kind]?.width ?? 90,
          Cell,
        },
        rowAction: spec,
      };
    });
  }, [specsKey, propertyMap, readOnly]);
}

/**
 * One row's button.
 *
 * Pressing it is a single commit, so it is rights-checked, synced, in history and
 * undoable for free. What it has to add is *feedback*: the press must read as
 * having happened while the commit is still in flight, which is why the button
 * goes busy and then briefly confirms — the same problem the timer's start/stop
 * had, solved once here.
 */
function RowActionCell({
  subject,
  spec,
  property,
}: {
  subject: string;
  spec: RowActionSpec;
  property: Property | undefined;
}): JSX.Element | null {
  const store = useStore();
  const row = useResource(subject);
  const [busy, setBusy] = useState(false);
  const [justRan, setJustRan] = useState(false);
  // A subscribing read, NOT `row.get(...)`: the React Compiler memoizes on the
  // resource proxy's identity, which does not change when the resource mutates
  // internally — so a render-time `get` left the button stuck on its first value
  // while the cell beside it showed the new one.
  const [current] = useValue(row, spec.property);
  // Subscribing for the same reason: `row.new` is a mutable field.
  const isDraft = useIsUnsavedDraft(row);

  const active = ROW_ACTION_GENERATORS[spec.kind]?.isActive?.(current) ?? false;

  // The trailing row of the grid is a purely local draft that has never been
  // committed, so there is nothing to patch yet. The cell itself still renders:
  // the grid lays out one element per column, and the cell is what draws the
  // row borders.
  if (!isRowActionComplete(spec) || isDraft) {
    return <CellBox />;
  }

  const run = () => {
    setBusy(true);
    void applyRowAction(row, spec, property)
      .then(() => {
        setJustRan(true);
        window.setTimeout(() => setJustRan(false), 800);
      })
      .catch(error => {
        // Never silent: a press that did nothing has to say so, or the user
        // presses again and cannot tell whether the first one worked.
        store.notifyError(error as Error);
      })
      .finally(() => setBusy(false));
  };

  return (
    <CellBox>
      <Button
        type='button'
        title={spec.label}
        aria-label={spec.label}
        data-kind={spec.kind}
        data-testid={`row-action-${spec.id}`}
        data-active={active}
        aria-pressed={
          ROW_ACTION_GENERATORS[spec.kind].isActive ? active : undefined
        }
        disabled={busy}
        $active={active}
        $confirming={justRan}
        onClick={run}
      >
        {spec.kind === 'toggle' ? <FaCheck size='0.75em' /> : spec.label}
      </Button>
    </CellBox>
  );
}

/* The grid cell: a real element per column, so it gets the row borders. */
const CellBox = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 0;
`;

/* Ghost pill (the shared `ghostButtonStyles`) centred in its cell, so it never
 * touches the row borders. A toggle is a round tick control instead. */
const Button = styled.button<{ $active: boolean; $confirming: boolean }>`
  ${ghostButtonStyles}
  display: flex;
  max-width: calc(100% - 0.5rem);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  background-color: ${p =>
    p.$confirming
      ? p.theme.colors.main
      : p.$active
        ? p.theme.colors.mainSelectedBg
        : 'transparent'};
  color: ${p =>
    p.$confirming
      ? p.theme.colors.bg
      : p.$active
        ? p.theme.colors.main
        : p.theme.colors.textLight};

  &:disabled {
    cursor: progress;
    opacity: 0.6;
  }

  &[data-kind='toggle'] {
    justify-content: center;
    width: 1.5rem;
    height: 1.5rem;
    padding: 0;
    border-radius: 50%;
    border: 1.5px solid
      ${p => (p.$active ? p.theme.colors.main : p.theme.colors.bg2)};
    background-color: ${p => (p.$active ? p.theme.colors.main : 'transparent')};
    color: ${p => (p.$active ? p.theme.colors.bg : 'transparent')};

    &:hover:not(:disabled) {
      border-color: ${p => p.theme.colors.main};
      color: ${p => (p.$active ? p.theme.colors.bg : p.theme.colors.main)};
      background-color: ${p =>
        p.$active ? p.theme.colors.main : 'transparent'};
    }
  }
`;
