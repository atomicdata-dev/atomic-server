import { Property, unknownSubject, useStore } from '@tomic/react';
import React, { useCallback, useId, useMemo, useState } from 'react';
import { ContainerFull } from '../../components/Containers';
import { EditableTitle } from '../../components/EditableTitle';
import { FancyTable } from '../../components/TableEditor';
import type { ResourcePageProps } from '../ResourcePage';
import { TableHeading } from './TableHeading';
import { useTableColumns } from './useTableColumns';
import { TableNewRow, TableRow } from './TableRow';
import { useTableData } from './useTableData';
import { NewColumnButton } from './NewColumnButton';
import { TablePageContext, TablePageContextType } from './tablePageContext';
import { useHandlePaste } from './helpers/useHandlePaste';
import { useHandleColumnResize } from './helpers/useHandleColumnResize';
import {
  createResourceDeletedHistoryItem,
  useTableHistory,
} from './helpers/useTableHistory';
import { useHandleClearCells } from './helpers/useHandleClearCells';
import { useHandleCopyCommand } from './helpers/useHandleCopyCommand';
import { ExpandedRowDialog } from './ExpandedRowDialog';

const columnToKey = (column: Property) => column.subject;

export function TablePage({ resource }: ResourcePageProps): JSX.Element {
  const store = useStore();
  const titleId = useId();

  const {
    tableClass,
    sorting,
    setSortBy,
    collection,
    invalidateCollection,
    collectionVersion,
  } = useTableData(resource);

  const { columns, reorderColumns } = useTableColumns(tableClass);

  const { undoLastItem, addItemsToHistoryStack } =
    useTableHistory(invalidateCollection);

  const handlePaste = useHandlePaste(
    resource,
    collection,
    tableClass,
    invalidateCollection,
    addItemsToHistoryStack,
    collectionVersion,
  );

  const [showExpandedRowDialog, setShowExpandedRowDialog] = useState(false);
  const [expandedRowSubject, setExpandedRowSubject] = useState<string>();

  const handleRowExpand = useCallback(
    async (index: number) => {
      const row = await collection.getMemberWithIndex(index);
      setExpandedRowSubject(row);
      setShowExpandedRowDialog(true);
    },
    [collection],
  );

  const tablePageContext: TablePageContextType = useMemo(
    () => ({
      tableClassResource: tableClass,
      sorting,
      setSortBy,
      addItemsToHistoryStack,
    }),
    [tableClass, setSortBy, sorting, addItemsToHistoryStack],
  );

  const handleDeleteRow = useCallback(
    async (index: number) => {
      const row = await collection.getMemberWithIndex(index);

      if (!row) {
        return;
      }

      const rowResource = store.getResourceLoading(row);
      addItemsToHistoryStack(createResourceDeletedHistoryItem(rowResource));

      await rowResource.destroy(store);

      invalidateCollection();
    },
    [collection, store, invalidateCollection],
  );

  const handleClearCells = useHandleClearCells(
    collection,
    addItemsToHistoryStack,
  );

  const handleCopyCommand = useHandleCopyCommand(collection, collectionVersion);

  const [columnSizes, handleColumnResize] = useHandleColumnResize(resource);

  const Row = useCallback(
    ({ index }: { index: number }) => {
      if (index < collection.totalMembers) {
        return (
          <TableRow collection={collection} index={index} columns={columns} />
        );
      }

      return (
        <TableNewRow
          parent={resource}
          columns={columns}
          index={index}
          invalidateTable={invalidateCollection}
        />
      );
    },
    [collection, columns, collectionVersion],
  );

  if (collectionVersion === 0) {
    return <ContainerFull>Loading...</ContainerFull>;
  }

  return (
    <ContainerFull>
      <TablePageContext.Provider value={tablePageContext}>
        <EditableTitle resource={resource} id={titleId} />
        <FancyTable
          columns={columns}
          columnSizes={columnSizes}
          itemCount={collection.totalMembers + 1}
          columnToKey={columnToKey}
          labelledBy={titleId}
          onClearRow={handleDeleteRow}
          onCellResize={handleColumnResize}
          onClearCells={handleClearCells}
          onCopyCommand={handleCopyCommand}
          onPasteCommand={handlePaste}
          onUndoCommand={undoLastItem}
          onColumnReorder={reorderColumns}
          onRowExpand={handleRowExpand}
          HeadingComponent={TableHeading}
          NewColumnButtonComponent={NewColumnButton}
        >
          {Row}
        </FancyTable>
        <ExpandedRowDialog
          subject={expandedRowSubject ?? unknownSubject}
          open={showExpandedRowDialog}
          bindOpen={setShowExpandedRowDialog}
        />
      </TablePageContext.Provider>
    </ContainerFull>
  );
}
