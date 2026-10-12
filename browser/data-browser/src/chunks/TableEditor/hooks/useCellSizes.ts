import { useCallback, useEffect, useState } from 'react';

/**
 * The row gutter. It holds the row number, the expand button that replaces it
 * when the gutter is hovered, and the row-scoped affordance slot beside them
 * (see `FancyTableProps.RowHeaderAddonComponent`). Wide enough for the widest
 * of those states — a comment bubble with a count next to the expand button —
 * so nothing in it is ever squeezed or clipped. The row-select tick box sits in
 * the same gutter, hence the extra room.
 */
const INDEX_CELL_WIDTH = '6.75rem';

const parseSize = (size: string) => {
  try {
    return Number.parseFloat(size.replace('px', ''));
  } catch (e) {
    console.error('parseSize error', e);

    return DEFAULT_SIZE_PX;
  }
};

const toPixels = (sizes: number[]) => sizes.map(x => `${x}px`);

export const DEFAULT_SIZE_PX = 300;
const DEFAULT_SIZE_STR = DEFAULT_SIZE_PX + 'px';

export function useCellSizes<T>(
  externalSizes: number[] | undefined,
  columns: T[],
  onSizesChange: (sizes: number[]) => void,
) {
  // CSS values for column sizes
  const [sizes, setSizes] = useState<string[]>(
    externalSizes
      ? toPixels(externalSizes)
      : Array(columns.length).fill(DEFAULT_SIZE_STR),
  );

  const resizeCell = useCallback(
    (index: number, size: string) => {
      if (sizes.length !== columns.length) {
        console.error('sizes.length !== columns.length', columns, sizes);
      }

      const newSizes = [...sizes];
      newSizes[index] = size;

      setSizes(newSizes);
      onSizesChange(newSizes.map(parseSize));
    },
    [columns, sizes, onSizesChange],
  );

  useEffect(() => {
    if (externalSizes) {
      setSizes(toPixels(externalSizes));
    }
  }, [externalSizes]);

  // Fit the size list to the column count. Via the updater form, NOT the `sizes`
  // from this render: when columns and `externalSizes` change in the same commit
  // (a view adding its own columns does exactly that), the effect above has
  // already applied the external widths, and appending to the stale list threw
  // them away — every view-added column then rendered at the 300px default
  // instead of the width it asked for.
  useEffect(() => {
    if (columns.length === 0) {
      return;
    }

    setSizes(current => {
      const diff = columns.length - current.length;

      if (diff === 0) {
        return current;
      }

      return diff > 0
        ? [...current, ...Array(diff).fill(DEFAULT_SIZE_STR)]
        : current.slice(0, columns.length);
    });
  }, [columns]);

  // The state above is corrected by effects, which run a frame after the render
  // that changed the columns. Rendering a size list that doesn't match the
  // columns paints the *previous* view's widths for that frame — very visible
  // when switching between views whose column counts differ, and it churns the
  // grid while it settles. So a mismatched list is ignored in favour of what the
  // caller passed (or plain defaults) until the state catches up.
  const effectiveSizes =
    sizes.length === columns.length
      ? sizes
      : externalSizes?.length === columns.length
        ? toPixels(externalSizes)
        : Array(columns.length).fill(DEFAULT_SIZE_STR);

  const templateColumns = `${INDEX_CELL_WIDTH} ${effectiveSizes.join(
    ' ',
  )} minmax(50px, 1fr)`;
  const contentRowWidth = `calc(${INDEX_CELL_WIDTH} + ${effectiveSizes.join(
    ' + ',
  )})`;

  return {
    /** CSS --table-template-columns */
    templateColumns,
    /** CSS --table-content-width */
    contentRowWidth,
    resizeCell,
  };
}
