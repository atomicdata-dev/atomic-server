import { useCallback } from 'react';
import { HistoryViewProps } from './HistoryViewProps';
import { styled } from 'styled-components';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Column } from '../../components/Row';
import { ResourceCardDefault } from '../../views/Card/ResourceCard';
import { VersionTitle } from './VersionTitle';
import { VersionScroller } from './VersionScroller';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../../components/Dialog';
import { Version } from '@tomic/react';

export function HistoryMobileView({
  resource,
  groupedVersions,
  selectedVersion,
  onSelectVersion,
  onVersionAccept,
}: HistoryViewProps) {
  const { dialogProps, show: showDialog, close: closeDialog } = useDialog();

  const handleVersionSelect = useCallback((version: Version) => {
    onSelectVersion(version);
    showDialog();
  }, []);

  return (
    <>
      <CenteredScroller
        title={`History of ${resource.title}`}
        subject={resource.getSubject()}
        groupedVersions={groupedVersions}
        selectedVersion={selectedVersion}
        onSelectVersion={handleVersionSelect}
      />
      <Dialog {...dialogProps}>
        <DialogTitle>
          <h1>Version</h1>
        </DialogTitle>
        <DialogContent>
          <Column fullHeight>
            {selectedVersion && selectedVersion?.resource && (
              <>
                <VersionTitle version={selectedVersion} />
                <StyledCard>
                  <ResourceCardDefault resource={selectedVersion.resource} />
                </StyledCard>
              </>
            )}
          </Column>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => closeDialog(false)} subtle>
            Cancel
          </Button>
          <Button onClick={onVersionAccept}>Make current version</Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

const StyledCard = styled(Card)`
  overflow: auto;
`;

const CenteredScroller = styled(VersionScroller)`
  margin-inline: auto;
`;
