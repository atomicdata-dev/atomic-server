import { unknownSubject } from '@tomic/react';
import { createContext } from 'react';
import { TableSorting } from './tableSorting';
import { AddItemToHistoryStack } from './helpers/useTableHistory';

export interface TablePageContextType {
  tableClassSubject: string;
  sorting: TableSorting;
  setSortBy: React.Dispatch<string>;
  addItemsToHistoryStack: AddItemToHistoryStack;
}

export const TablePageContext = createContext<TablePageContextType>({
  tableClassSubject: unknownSubject,
  sorting: {
    prop: '',
    sortDesc: true,
  },
  setSortBy: () => undefined,
  addItemsToHistoryStack: () => undefined,
});
