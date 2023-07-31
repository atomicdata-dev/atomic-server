import {
  Resource,
  urls,
  useCollection,
  UseCollectionResult,
  useResource,
  useSubject,
} from '@tomic/react';
import { useMemo, useReducer } from 'react';
import { TableSorting, DEFAULT_SORT_PROP } from './tableSorting';

const PAGE_SIZE = 30;
const DEFAULT_SORT = {
  prop: DEFAULT_SORT_PROP,
  sortDesc: false,
};

type UseTableDataResult = {
  tableClass: Resource;
  sorting: TableSorting;
  setSortBy: React.Dispatch<string>;
} & UseCollectionResult;

const useTableSorting = () =>
  useReducer<(state: TableSorting, property: string) => TableSorting>(
    (state, property) => {
      if (state.prop === property && state.sortDesc) {
        return DEFAULT_SORT;
      }

      if (state.prop === property) {
        return {
          ...state,
          sortDesc: true,
        };
      }

      return {
        prop: property,
        sortDesc: false,
      };
    },
    DEFAULT_SORT,
  );

export function useTableData(resource: Resource): UseTableDataResult {
  const [sorting, setSortBy] = useTableSorting();

  const [classSubject] = useSubject(resource, urls.properties.classType);
  const tableClass = useResource(classSubject);

  const queryFilter = useMemo(
    () => ({
      property: urls.properties.parent,
      value: resource.getSubject(),
      sort_by: sorting.prop,
      sort_desc: sorting.sortDesc,
    }),
    [resource.getSubject(), sorting.prop, sorting.sortDesc],
  );

  return {
    tableClass,
    sorting,
    setSortBy,
    ...useCollection(queryFilter, PAGE_SIZE),
  };
}
