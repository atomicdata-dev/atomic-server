import { useCallback, useEffect, useState } from 'react';

const INDEX_CELL_WIDTH = '6ch';

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
      setSizes(prevSizes => {
        if (prevSizes.length !== columns.length) {
          console.error(
            'prevSizes.length !== columns.length',
            columns,
            prevSizes,
          );
        }

        const newSizes = [...prevSizes];
        newSizes[index] = size;

        return newSizes;
      });

      onSizesChange(sizes.map(parseSize));
    },
    [columns, sizes, onSizesChange],
  );

  useEffect(() => {
    if (externalSizes) {
      setSizes(toPixels(externalSizes));
    }
  }, [externalSizes]);

  useEffect(() => {
    const diff = columns.length - sizes.length;

    if (diff > 0) {
      setSizes([...sizes, ...Array(diff).fill(DEFAULT_SIZE_STR)]);
    }

    if (diff < 0) {
      setSizes(sizes.slice(0, columns.length));
    }
  }, [columns]);

  const templateColumns = `${INDEX_CELL_WIDTH} ${sizes.join(
    ' ',
  )} minmax(50px, 1fr)`;
  const contentRowWidth = `calc(${INDEX_CELL_WIDTH} + ${sizes.join(' + ')})`;

  return {
    /** CSS --table-template-columns */
    templateColumns,
    /** CSS --table-content-width */
    contentRowWidth,
    resizeCell,
  };
}
