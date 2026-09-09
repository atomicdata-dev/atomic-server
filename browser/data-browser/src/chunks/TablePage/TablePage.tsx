import { core, useString, useResource, useCanWrite } from '@tomic/react';
import { useNavigate } from '@tanstack/react-router';
import { ShowRoute } from '../../routes/ShowRoute';
import { useTableFormColumns } from '../FormBuilder/useTableFormColumns';
import { EditPropertyDialog } from './PropertyForm/EditPropertyDialog';
import { useId, useMemo, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { ContainerFull } from '@components/Containers';
import { EditableTitle } from '@components/EditableTitle';
import { ResourceCoverImage } from '@components/ResourceDecorations';
import type { ResourcePageProps } from '@views/ResourcePage';
import { Row as FlexRow, Column } from '@components/Row';
import { FaFileCsv } from 'react-icons/fa6';
import { TableForms } from './TableForms';
import { TableExportDialog } from './TableExportDialog';
import { TableResource } from './TableResource';
import { useCustomContextItems } from '@components/ResourceContextMenu/CustomContextItemsContext';
import { DIVIDER } from '@components/Dropdown';

export function TablePage({ resource }: ResourcePageProps): JSX.Element {
  const titleId = useId();
  const search = ShowRoute.useSearch();
  const navigate = useNavigate();
  const column = useResource(search.editColumn);
  const [classSubject] = useString(resource, core.properties.classtype);
  const { columns } = useTableFormColumns(classSubject ?? '');
  const canWrite = useCanWrite(resource);
  const editColumn =
    !!search.editColumn &&
    canWrite &&
    columns.some(p => p.subject === search.editColumn);

  const [showExportDialog, setShowExportDialog] = useState(false);

  const customMenuItems = useMemo(
    () => [
      DIVIDER,
      {
        id: 'export-csv',
        label: 'Export to CSV',
        onClick: () => setShowExportDialog(true),
        icon: <FaFileCsv />,
      },
    ],
    [],
  );

  useCustomContextItems(customMenuItems);

  const focusTable = () => {
    // Focus the first editable cell (row 0, col 1)
    const firstCell = document.querySelector<HTMLElement>(
      '[role="row"][aria-rowindex="2"] > [role="gridcell"][aria-colindex="2"]',
    );

    if (firstCell) {
      firstCell.dispatchEvent(
        new MouseEvent('mousedown', { bubbles: true, cancelable: true }),
      );
      firstCell.focus();
    } else {
      document.querySelector<HTMLElement>('[role="grid"]')?.focus();
    }
  };

  return (
    <>
      <ResourceCoverImage resource={resource} />
      {editColumn && (
        <EditPropertyDialog
          resource={column}
          showDialog
          bindShow={visible => {
            if (!visible)
              void navigate({
                to: ShowRoute.fullPath,
                search: { ...search, editColumn: undefined },
                replace: true,
              });
          }}
        />
      )}
      <BoundedHeightContainer>
        <Column>
          <FlexRow justify='space-between'>
            <EditableTitle
              resource={resource}
              id={titleId}
              onCommit={focusTable}
              withDecorations
            />
          </FlexRow>
          <TableResource resource={resource} />
          <TableForms table={resource} />
        </Column>
        <TableExportDialog
          subject={resource.subject}
          show={showExportDialog}
          bindShow={setShowExportDialog}
        />
      </BoundedHeightContainer>
    </>
  );
}

/**
 * Every view on this page sizes itself to the page rather than to its content,
 * so the 10rem of scroll room `ContainerFull` keeps below a document would be
 * empty space you can scroll the table's header row out of view to reach.
 */
const BoundedHeightContainer = styled(ContainerFull)`
  padding-bottom: ${p => p.theme.size()};
`;
