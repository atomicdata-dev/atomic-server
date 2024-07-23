import {
  core,
  Resource,
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

  const [classSubject] = useSubject(resource, core.properties.classtype);
  const tableClass = useResource(classSubject);

  const queryFilter = useMemo(
    () => ({
      property: core.properties.parent,
      value: resource.subject,
      sort_by: sorting.prop,
      sort_desc: sorting.sortDesc,
    }),
    [resource.subject, sorting.prop, sorting.sortDesc],
  );

  return {
    tableClass,
    sorting,
    setSortBy,
    ...useCollection(queryFilter, {
      pageSize: PAGE_SIZE,
      server: new URL(resource.subject).origin,
    }),
  };
}
