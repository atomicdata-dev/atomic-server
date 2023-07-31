import { Resource, useStore, urls, useArray, Property } from '@tomic/react';
import { useCallback, useEffect, useState } from 'react';
import { reorderArray } from '../../components/TableEditor';

type UseTableColumnsReturnType = {
  columns: Property[];
  reorderColumns: (
    sourceIndex: number,
    destinationIndex: number,
  ) => Promise<void>;
};

const valueOpts = {
  commit: true,
};

export function useTableColumns(
  tableClass: Resource,
): UseTableColumnsReturnType {
  const store = useStore();

  const [requiredProps, setRequiredProps] = useArray(
    tableClass,
    urls.properties.requires,
    valueOpts,
  );
  const [recommendedProps, setRecommendedProps] = useArray(
    tableClass,
    urls.properties.recommends,
    valueOpts,
  );

  const [columns, setColumns] = useState<Property[]>([]);

  const reorderColumns = useCallback(
    async (sourceIndex: number, destinationIndex: number): Promise<void> => {
      const newColumns = reorderArray(columns, sourceIndex, destinationIndex);
      const subjects = newColumns.map(c => c.subject);

      const newRequiredProps = subjects.filter(c => requiredProps.includes(c));
      const newRecommendedProps = subjects.filter(c =>
        recommendedProps.includes(c),
      );

      await setRequiredProps(newRequiredProps);
      await setRecommendedProps(newRecommendedProps);
    },
    [
      requiredProps,
      recommendedProps,
      setRecommendedProps,
      setRequiredProps,
      columns,
    ],
  );

  useEffect(() => {
    const props = [...requiredProps, ...recommendedProps];

    Promise.all(props.map(prop => store.getProperty(prop))).then(newColumns => {
      setColumns(newColumns);
    });
  }, [requiredProps, recommendedProps]);

  return { columns, reorderColumns };
}
