import { Datatype, core, useCanWrite, type Server } from '@tomic/react';
import { ContainerNarrow } from '@components/Containers';
import { Button } from '@components/Button';
import { useSettings } from '@helpers/AppSettings';
import { ResourcePageProps } from '../ResourcePage';
import { EditableTitle } from '@components/EditableTitle';
import { useVisibleDriveChildren } from '@hooks/useVisibleDriveChildren';
import { useIsPrivateDrive } from '@hooks/useIsPrivateDrive';
import { PrivateDriveBadge } from '@components/Drives/PrivateDriveBadge';
import { ResourceCoverImage } from '@components/ResourceDecorations';
import { Column, Row } from '@components/Row';
import {
  DriveSwitcher,
  DriveSwitcherChevronTrigger,
} from '@components/SideBar/DriveSwitcher';
import { styled } from 'styled-components';
import { useDialog } from '@components/Dialog/useDialog';
import { FaGear } from 'react-icons/fa6';
import type { JSX } from 'react';
import { useVectorIndexStatus } from '@hooks/useVectorIndexStatus';
import { VectorIndexingIndicator } from '@components/VectorIndexingIndicator';
import { ValueFormAddButton } from '@components/forms/ValueForm/ValueFormAddButton';
import { FileDropZone } from '@components/forms/FileDropzone/FileDropzone';
import { DriveSettingsDialog } from './DriveSettingsDialog';
import {
  ActivityFeed,
  DrivePeople,
  QuickCreateCards,
  RecentlyOpened,
  ResourceTiles,
  SectionTitle,
} from './DriveHome';

/** A View for Drives, which function similar to a homepage or dashboard. */
function DrivePage({ resource }: ResourcePageProps<Server.Drive>): JSX.Element {
  const { drive: baseURL, setDrive: setBaseURL } = useSettings();
  const { subjects: subResources } = useVisibleDriveChildren(resource.subject);
  const [dialogProps, showSettings, , settingsOpen] = useDialog();

  const vectorIndexing = useVectorIndexStatus();

  const canEdit = useCanWrite(resource);
  const isPrivateDrive = useIsPrivateDrive(resource.subject);

  if (!baseURL) {
    setBaseURL(resource.subject);
  }

  return (
    <>
      <ResourceCoverImage resource={resource} />
      <FileDropZone parentResource={resource}>
        <ContainerNarrow>
          <Column gap='2rem'>
            <Header>
              <Row align='center' wrapItems gap='1rem'>
                <EditableTitle
                  resource={resource}
                  withDecorations
                  // Its subject is derived from your key: there is exactly one and
                  // it cannot be swapped. A name like "Q3 Launch" on it would be a
                  // name that lies about what the thing is.
                  lockedReason={
                    isPrivateDrive
                      ? 'Your private drive keeps its name. It is tied to your account, not to a project.'
                      : undefined
                  }
                />
                <DriveSwitcher Trigger={DriveSwitcherChevronTrigger} />
                {isPrivateDrive && <PrivateDriveBadge />}
                {vectorIndexing && <VectorIndexingIndicator />}
              </Row>
              <Row align='center' wrapItems gap='0.75rem'>
                <DrivePeople />
                {baseURL !== resource.subject && (
                  <Button subtle onClick={() => setBaseURL(resource.subject)}>
                    Set as current drive
                  </Button>
                )}
                <Button
                  subtle
                  onClick={showSettings}
                  data-testid='drive-settings-button'
                >
                  <FaGear /> Drive settings
                </Button>
              </Row>
            </Header>

            <ValueFormAddButton
              resource={resource}
              propertyURL={core.properties.description}
              datatype={Datatype.MARKDOWN}
              buttonLabel='Add description'
            />

            <RecentlyOpened drive={resource.subject} />

            <ActivityFeed
              subjects={subResources}
              drive={resource.subject}
              title='Activity'
            />

            <section>
              <SectionTitle>Resources</SectionTitle>
              {subResources.length > 0 ? (
                <ResourceTiles subjects={subResources} />
              ) : (
                <EmptyHint>
                  {canEdit
                    ? 'Nothing here yet. Create something with New, or drop files on this page.'
                    : 'Nothing here yet.'}
                </EmptyHint>
              )}
            </section>

            {canEdit && <QuickCreateCards parent={resource.subject} />}
          </Column>
        </ContainerNarrow>
      </FileDropZone>
      <DriveSettingsDialog
        drive={resource}
        dialogProps={dialogProps}
        isOpen={settingsOpen}
      />
    </>
  );
}

export default DrivePage;

const Header = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 1rem;
`;

const EmptyHint = styled.p`
  color: ${p => p.theme.colors.textLight};
`;
