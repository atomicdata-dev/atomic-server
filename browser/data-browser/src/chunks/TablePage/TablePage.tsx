import { useId, useMemo, useState, lazy, Suspense, type JSX } from 'react';
import { styled } from 'styled-components';
import { ContainerFull } from '@components/Containers';
import { EditableTitle } from '@components/EditableTitle';
import { ResourceCoverImage } from '@components/ResourceDecorations';
import type { ResourcePageProps } from '@views/ResourcePage';
import { Row as FlexRow, Column } from '@components/Row';
import { FaFileCsv } from 'react-icons/fa6';
import { TableExportDialog } from './TableExportDialog';
import { TableResource } from './TableResource';
import { useCustomContextItems } from '@components/ResourceContextMenu/CustomContextItemsContext';
import { DIVIDER } from '@components/Dropdown';

const WorkspaceControls = lazy(() =>
  import('../PluginRuns/WorkspaceControls').then(m => ({
    default: m.WorkspaceControls,
  })),
);

export function TablePage({ resource }: ResourcePageProps): JSX.Element {
  const titleId = useId();

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
          <Suspense fallback={null}>
            <WorkspaceControls workspace={resource.subject} />
          </Suspense>
          <TableResource resource={resource} />
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
