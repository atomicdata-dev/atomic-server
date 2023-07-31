import { Resource, urls, useString } from '@tomic/react';
import { useCallback, useDeferredValue, useMemo } from 'react';

const valueOpts = {
  commit: true,
  commitDebounce: 1000,
};

export function useHandleColumnResize(
  table: Resource,
): [number[] | undefined, (sizes: number[]) => void] {
  const [columnWidths, setColumnWidths] = useString(
    table,
    urls.properties.table.tableColumnWidths,
    valueOpts,
  );

  const handleColumnResize = useCallback(
    async (sizes: number[]) => {
      const value = JSON.stringify(sizes);

      setColumnWidths(value);
    },
    [setColumnWidths],
  );

  const deferredWidths = useDeferredValue(columnWidths);

  const parsedColumnWidths = useMemo(() => {
    const parsed = JSON.parse(deferredWidths ?? '[]') as number[];

    return parsed.length > 0 ? parsed : undefined;
  }, [deferredWidths]);

  return [parsedColumnWidths, handleColumnResize];
}
