import { Property, unknownSubject, useStore } from '@tomic/react';
import { useCallback, useId, useMemo, useState } from 'react';
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
import { Row as FlexRow, Column } from '../../components/Row';
import { useHandleClearCells } from './helpers/useHandleClearCells';
import { useHandleCopyCommand } from './helpers/useHandleCopyCommand';
import { ExpandedRowDialog } from './ExpandedRowDialog';
import { IconButton } from '../../components/IconButton/IconButton';
import { FaCode, FaFileCsv } from 'react-icons/fa6';
import { ResourceCodeUsageDialog } from '../CodeUsage/ResourceCodeUsageDialog';
import { TableExportDialog } from './TableExportDialog';

const columnToKey = (column: Property) => column.subject;

export function TablePage({ resource }: ResourcePageProps): JSX.Element {
  const store = useStore();
  const titleId = useId();

  const [showCodeUsageDialog, setShowCodeUsageDialog] = useState(false);
  const [showExportDialog, setShowExportDialog] = useState(false);
  const { tableClass, sorting, setSortBy, collection, invalidateCollection } =
    useTableData(resource);

  const { columns, reorderColumns } = useTableColumns(tableClass);

  const { undoLastItem, addItemsToHistoryStack } =
    useTableHistory(invalidateCollection);

  const handlePaste = useHandlePaste(
    resource,
    collection,
    tableClass,
    invalidateCollection,
    addItemsToHistoryStack,
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
      tableClassSubject: tableClass.subject,
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

      await rowResource.destroy();

      invalidateCollection();
    },
    [collection, store, invalidateCollection],
  );

  const handleClearCells = useHandleClearCells(
    collection,
    addItemsToHistoryStack,
  );

  const handleCopyCommand = useHandleCopyCommand(collection);

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
    [collection, columns],
  );

  return (
    <ContainerFull>
      <TablePageContext.Provider value={tablePageContext}>
        <Column>
          <FlexRow justify='space-between'>
            <EditableTitle resource={resource} id={titleId} />
            <FlexRow style={{ marginRight: '1rem' }}>
              <IconButton
                title='Use in code'
                onClick={() => setShowCodeUsageDialog(true)}
              >
                <FaCode />
              </IconButton>
              <IconButton
                title='Use in code'
                onClick={() => setShowExportDialog(true)}
              >
                <FaFileCsv />
              </IconButton>
            </FlexRow>
          </FlexRow>
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
        </Column>
        <ExpandedRowDialog
          subject={expandedRowSubject ?? unknownSubject}
          open={showExpandedRowDialog}
          bindOpen={setShowExpandedRowDialog}
        />
      </TablePageContext.Provider>
      <ResourceCodeUsageDialog
        subject={resource.subject}
        show={showCodeUsageDialog}
        bindShow={setShowCodeUsageDialog}
      />
      <TableExportDialog
        subject={resource.subject}
        show={showExportDialog}
        bindShow={setShowExportDialog}
      />
    </ContainerFull>
  );
}
