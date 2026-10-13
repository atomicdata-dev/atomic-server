import { useEffectiveConstraint, type Constraint } from '@tomic/react';
import { useContext } from 'react';
import { TablePageContext } from './tablePageContext';

/**
 * The constraint of a column (property) for the table being shown: its row
 * class's `constraints` map, falling back to the Property's legacy
 * `allowsOnly`, `classtype` and `min`/`max`. Pass `classSubject` where the
 * caller already knows the row class (outside the table page context).
 */
export function useColumnConstraint(
  propertySubject: string | undefined,
  classSubject?: string,
): Constraint {
  const { tableClassSubject } = useContext(TablePageContext);

  return useEffectiveConstraint(
    [classSubject ?? tableClassSubject],
    propertySubject,
  );
}

/**
 * The constraint of a column for one row: the row's own classes, plus the
 * table's row class. A row that is not yet saved (the first row of a table)
 * may not list its class yet, and would otherwise lose every option and
 * linked class its column has.
 */
export function useRowConstraint(
  rowClasses: string[],
  propertySubject: string | undefined,
): Constraint {
  const { tableClassSubject } = useContext(TablePageContext);
  const classes = tableClassSubject
    ? Array.from(new Set([...rowClasses, tableClassSubject]))
    : rowClasses;

  return useEffectiveConstraint(classes, propertySubject);
}

export { optionSubjects, withConstraint } from '@helpers/withConstraint';
