import { Resource, unknownSubject } from '@tomic/react';
import { createContext } from 'react';
import { TableSorting } from './tableSorting';
import { AddItemToHistoryStack } from './helpers/useTableHistory';

export interface TablePageContextType {
  tableClassResource: Resource;
  sorting: TableSorting;
  setSortBy: React.Dispatch<string>;
  addItemsToHistoryStack: AddItemToHistoryStack;
}

export const TablePageContext = createContext<TablePageContextType>({
  tableClassResource: new Resource(unknownSubject),
  sorting: {
    prop: '',
    sortDesc: true,
  },
  setSortBy: () => undefined,
  addItemsToHistoryStack: () => undefined,
});
