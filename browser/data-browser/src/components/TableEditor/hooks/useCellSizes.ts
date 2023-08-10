import { useCallback, useEffect, useState } from 'react';

const INDEX_CELL_WIDTH = '6ch';

const parseSize = (size: string) => Number.parseFloat(size.replace('px', ''));

const toPixels = (sizes: number[]) => sizes.map(x => `${x}px`);

export function useCellSizes<T>(
  externalSizes: number[] | undefined,
  columns: T[],
  onSizesChange: (sizes: number[]) => void,
) {
  const amountOfColumns = columns.length;
  const [sizes, setSizes] = useState<string[]>(
    externalSizes
      ? toPixels(externalSizes)
      : Array(amountOfColumns).fill('300px'),
  );

  const resizeCell = useCallback(
    (index: number, size: string) => {
      setSizes(prevSizes => {
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

  const templateColumns = `${INDEX_CELL_WIDTH} ${sizes.join(
    ' ',
  )} minmax(50px, 1fr)`;
  const contentRowWidth = `calc(${INDEX_CELL_WIDTH} + ${sizes.join(' + ')})`;

  return {
    templateColumns,
    contentRowWidth,
    resizeCell,
  };
}
