import { driveDisplayName } from '../../helpers/driveDisplayName';
import {
  dataBrowser,
  useCanWrite,
  useResource,
  useStore,
  useString,
  useSubject,
  useTitle,
} from '@tomic/react';
import { Fragment, useEffect, useMemo, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { useSettings } from '../../helpers/AppSettings';
import { Button } from '../Button';
import { ResourceSideBar } from './ResourceSideBar/ResourceSideBar';
import { SidebarSelectionProvider } from './ResourceSideBar/SidebarSelection';
import { SideBarHeader } from './SideBarHeader';
import { SimpleErrorBlock } from '../ErrorLook';
import { DriveSwitcher } from './DriveSwitcher';
import { Row } from '../Row';
import type { DropdownTriggerProps } from '../Dropdown/DropdownTrigger';
import { LuChevronsUpDown } from 'react-icons/lu';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { ScrollArea } from '../ScrollArea';
import { DropEdge } from './ResourceSideBar/DropEdge';
import { SIDEBAR_CHILD_LIMIT, SideBarMoreRow } from './SideBarMoreRow';
import { LoaderInline } from '../Loader';
import { QuickCreateRow } from '../NewInstanceButton';
import { ResourceGlyph } from '../ResourceGlyph';
import { useIsPrivateDrive } from '../../hooks/useIsPrivateDrive';
import { useVisibleDriveChildren } from '../../hooks/useVisibleDriveChildren';

interface SideBarDriveProps {
  onItemClick: () => unknown;
}

/**
 * Shows the current Drive, it's children and an option to change to a different Drive.
 * Must render inside the sidebar's `DndContext` (see `SideBar`).
 */
export function SideBarDrive({ onItemClick }: SideBarDriveProps): JSX.Element {
  const store = useStore();
  const { drive, agent } = useSettings();
  const driveResource = useResource(drive);
  const {
    subjects: subResources,
    allSubjects: allChildren,
    loading: childrenLoading,
    total: totalChildren,
  } = useVisibleDriveChildren(drive, { limit: SIDEBAR_CHILD_LIMIT });
  const agentCanWrite = useCanWrite(driveResource);
  const [currentSubject] = useCurrentSubject();
  const currentResource = useResource(currentSubject);
  const [ancestry, setAncestry] = useState<string[]>([]);
  // One array for the whole render: a fresh `[drive]` per render defeats the
  // memo on every top-level row, and with it the rows below.
  const driveHierarchy = useMemo(() => [drive], [drive]);

  useEffect(() => {
    store.getResourceAncestry(currentResource.stable).then(result => {
      setAncestry(result);
    });
  }, [store, currentResource.stable]);

  return (
    <>
      <SideBarHeader>
        <DriveSwitcher Trigger={DriveSwitcherTrigger} onSwitch={onItemClick} />
      </SideBarHeader>
      <SidebarSelectionProvider current={currentSubject} ancestry={ancestry}>
        <StyledScrollArea>
          <ListWrapper>
            <DropEdge
              parentHierarchy={driveHierarchy}
              index={0}
              prevSubject={undefined}
              nextSubject={subResources[0]}
            />
            {/* Gate on `subResources` (reactive `useChildren` state), NOT on
                `driveResource.isReady()`. The latter is a proxy read the React
                Compiler memoizes on the stable ref, so when the drive flips to
                ready it doesn't re-render and the sidebar stays empty even
                though the children are in state (confirmed: `setSubjects([3])`
                ran but the list rendered nothing). If we HAVE children, show
                them; otherwise fall back to a loader / error. */}
            {subResources.length > 0 ? (
              subResources.map((child, index) => {
                return (
                  <Fragment key={child}>
                    <ResourceSideBar
                      subject={child}
                      renderedHierarchy={driveHierarchy}
                      onClick={onItemClick}
                    />
                    <DropEdge
                      parentHierarchy={driveHierarchy}
                      index={index + 1}
                      prevSubject={child}
                      nextSubject={subResources[index + 1]}
                    />
                  </Fragment>
                );
              })
            ) : childrenLoading ? (
              <SideBarLoader />
            ) : driveResource.error ? (
              <SideBarErr>
                {driveResource.isUnauthorized()
                  ? agent
                    ? 'unauthorized'
                    : 'This drive is private, sign in to view it'
                  : driveResource.error.message}
              </SideBarErr>
            ) : null}
            {totalChildren > allChildren.length && (
              <SideBarMoreRow
                parent={drive}
                hidden={totalChildren - allChildren.length}
                onClick={onItemClick}
              />
            )}
            {agentCanWrite && (
              <NewResourceRow gap='0' center>
                <QuickCreateRow
                  parent={drive}
                  newResourceButtonTestId='sidebar-new-resource'
                  highlightUntilUsed
                  onItemClick={onItemClick}
                />
              </NewResourceRow>
            )}
          </ListWrapper>
        </StyledScrollArea>
      </SidebarSelectionProvider>
    </>
  );
}

const DriveGlyph = styled.span`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  font-size: 1rem;
  line-height: 1;
  color: ${p => p.theme.colors.textLight};
`;

const DriveTitle = styled.h2`
  margin: 0;
  padding: 0;
  font-size: 1.05rem;
  font-weight: 600;
  line-height: 1.2;
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const Chevron = styled(LuChevronsUpDown)`
  flex-shrink: 0;
  margin-left: auto;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;

/** The whole header is one button: glyph, drive name and a hint chevron. */
const TriggerButton = styled(Button)<{ current?: boolean }>`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  text-align: left;
  flex: 1;
  min-width: 0;
  padding: 0.35rem 0.5rem;
  border: none;

  ${({ current, theme }) => current && `color: ${theme.colors.main};`}

  @media (hover: hover) {
    &:hover {
      background-color: ${props => props.theme.colors.bg1};
    }
  }
  &:active {
    background-color: ${props => props.theme.colors.bg2};
  }
`;

function DriveSwitcherTrigger({
  onClick,
  menuId,
  isActive,
  ref,
  id,
}: DropdownTriggerProps) {
  const { drive, showSidebarIcons } = useSettings();
  const driveResource = useResource(drive);
  const [title] = useTitle(driveResource);
  const isPrivateDrive = useIsPrivateDrive(drive);
  const [currentSubject] = useCurrentSubject();
  // A drive with its own emoji or icon shows that; the private drive is
  // "home" by default, any other drive falls back to the class icon.
  const [driveEmoji] = useString(driveResource, dataBrowser.properties.emoji);
  const [driveIcon] = useSubject(driveResource, dataBrowser.properties.icon);
  const hasCustomGlyph = !!(driveEmoji || driveIcon);
  const driveName = driveResource.isUnauthorized()
    ? 'Unauthorized'
    : driveDisplayName(driveResource.error ? undefined : title, drive);

  return (
    <TriggerButton
      clean
      current={drive === currentSubject}
      id={id}
      aria-controls={menuId}
      aria-expanded={isActive}
      aria-haspopup='menu'
      onClick={onClick}
      ref={ref}
      title='Switch Drive'
      data-testid='sidebar-drive-switcher'
    >
      {showSidebarIcons && (
        <DriveGlyph aria-hidden>
          {!hasCustomGlyph && isPrivateDrive ? (
            '🏠'
          ) : (
            <ResourceGlyph resource={driveResource} />
          )}
        </DriveGlyph>
      )}
      <DriveTitle data-testid='current-drive-title'>{driveName}</DriveTitle>
      <Chevron aria-hidden />
    </TriggerButton>
  );
}

const SideBarErr = styled(SimpleErrorBlock)`
  margin-inline-end: ${props => props.theme.size()};
`;

const ListWrapper = styled.div`
  overflow-x: hidden;
  position: relative;
  padding-inline: ${p => p.theme.margin}rem;
`;

const StyledScrollArea = styled(ScrollArea)`
  overflow: hidden;
`;

const SideBarLoader = styled(LoaderInline)`
  display: block;
  height: 1.5rem;
  margin-block: 0.3rem;
`;

const NewResourceRow = styled(Row)`
  padding-bottom: 1rem;
  overflow: visible;
`;
