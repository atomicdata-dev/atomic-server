import { driveDisplayName } from '../../helpers/driveDisplayName';
import {
  ai,
  dataBrowser,
  notifications,
  server,
  useCanWrite,
  useChildren,
  useResource,
  useStore,
  useString,
  useSubject,
  useTitle,
} from '@tomic/react';
import { canonicalizeScheme } from '@tomic/lib';
import { Fragment, useEffect, useMemo, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { useSettings } from '../../helpers/AppSettings';
import { constructOpenURL } from '../../helpers/navigation';
import { Button } from '../Button';
import { ResourceSideBar } from './ResourceSideBar/ResourceSideBar';
import { SidebarSelectionProvider } from './ResourceSideBar/SidebarSelection';
import { SideBarHeader } from './SideBarHeader';
import { SimpleErrorBlock } from '../ErrorLook';
import { DriveSwitcher } from './DriveSwitcher';
import { Row } from '../Row';
import { IconButton } from '../IconButton/IconButton';
import { buildDefaultTrigger } from '../Dropdown/DefaultTrigger';
import { LuChevronsUpDown } from 'react-icons/lu';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { ScrollArea } from '../ScrollArea';
import { DropEdge } from './ResourceSideBar/DropEdge';
import { SIDEBAR_CHILD_LIMIT, SideBarMoreRow } from './SideBarMoreRow';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { LoaderInline } from '../Loader';
import { QuickCreateRow } from '../NewInstanceButton';
import { ResourceGlyph } from '../ResourceGlyph';
import { useIsPrivateDrive } from '../../hooks/useIsPrivateDrive';

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
    subjects: allChildren,
    loading: childrenLoading,
    total: totalChildren,
  } = useChildren(drive, { limit: SIDEBAR_CHILD_LIMIT });

  // The drive's default ontology is schema plumbing (auto-created by
  // `createDrive`) — hide it from the tree so users aren't confronted with an
  // "Ontology" they never made. It stays reachable via the drive page and
  // class/property links. Ontologies the user creates themselves still show.
  const [defaultOntology] = useString(
    driveResource,
    server.properties.defaultOntology,
  );
  // Same for the Comments folder (the standard location holding comment
  // Messages, created lazily on the first comment): comments are reached
  // through the Comments panel, not by browsing the folder.
  const [commentsFolder] = useString(
    driveResource,
    dataBrowser.properties.commentsFolder,
  );
  // And the AI Chats folder (on the personal drive): chats re-open through
  // the AI sidebar on the resource they were started on.
  const [aiChatsFolder] = useString(driveResource, ai.properties.aiChatsFolder);
  // And the Inbox (on the personal drive): it opens from Notifications in the
  // app menu.
  const [inbox] = useString(driveResource, notifications.properties.inbox);
  // And the Trash folder: reached from the account menu at the bottom of the sidebar.
  const [trashFolder] = useString(
    driveResource,
    dataBrowser.properties.trashFolder,
  );
  const subResources = useMemo(
    () =>
      allChildren.filter(subject => {
        const canonical = canonicalizeScheme(subject);

        return (
          canonical !== canonicalizeScheme(defaultOntology ?? '') &&
          canonical !== canonicalizeScheme(commentsFolder ?? '') &&
          canonical !== canonicalizeScheme(aiChatsFolder ?? '') &&
          canonical !== canonicalizeScheme(inbox ?? '') &&
          canonical !== canonicalizeScheme(trashFolder ?? '')
        );
      }),
    [
      allChildren,
      defaultOntology,
      commentsFolder,
      aiChatsFolder,
      inbox,
      trashFolder,
    ],
  );
  const [title] = useTitle(driveResource);
  const isPrivateDrive = useIsPrivateDrive(drive);
  // A drive with its own emoji or icon shows that; the private drive is
  // "home" by default, any other drive falls back to the class icon.
  const [driveEmoji] = useString(driveResource, dataBrowser.properties.emoji);
  const [driveIcon] = useSubject(driveResource, dataBrowser.properties.icon);
  const hasCustomGlyph = !!(driveEmoji || driveIcon);
  const navigate = useNavigateWithTransition();
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

  const driveName = driveResource.isUnauthorized()
    ? 'Unauthorized'
    : driveDisplayName(driveResource.error ? undefined : title, drive);

  return (
    <>
      <SideBarHeader>
        <TitleButton
          resource={drive}
          clean
          current={drive === currentSubject}
          data-testid='sidebar-drive-open'
          onClick={() => {
            onItemClick();
            navigate(constructOpenURL(drive));
          }}
        >
          <DriveGlyph aria-hidden>
            {!hasCustomGlyph && isPrivateDrive ? (
              '🏠'
            ) : (
              <ResourceGlyph resource={driveResource} />
            )}
          </DriveGlyph>
          <DriveTitle data-testid='current-drive-title'>{driveName}</DriveTitle>
        </TitleButton>
        <DriveSwitcher Trigger={DriveSwitcherTrigger} />
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

/**
 * The title and the drive-switcher caret form one segmented control: a
 * flush inner edges, shared outer rounding, each
 * half highlighting on its own hover.
 */
const TitleButton = styled(Button)<{ current?: boolean }>`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  text-align: left;
  /* Fill the header so the switcher caret is always pinned to the right;
     the name truncates when longer than the sidebar. */
  flex: 1;
  min-width: 0;
  padding: 0.35rem 0.5rem;
  border: none;
  border-radius: ${props => props.theme.radius} 0 0
    ${props => props.theme.radius};

  ${({ current, theme }) =>
    current &&
    `
    color: ${theme.colors.main};
  `}

  &:hover {
    background-color: ${props => props.theme.colors.bg1};
  }
  &:active {
    background-color: ${props => props.theme.colors.bg2};
  }
`;

const SwitcherButton = styled(IconButton)`
  align-self: stretch;
  height: auto;
  width: auto;
  padding-inline: 0.35rem;
  border: none;
  border-radius: 0 ${p => p.theme.radius} ${p => p.theme.radius} 0;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;

  &:hover,
  &:focus-visible {
    background-color: ${p => p.theme.colors.bg1};
    color: ${p => p.theme.colors.text};
  }
  &:active {
    background-color: ${p => p.theme.colors.bg2};
  }
`;

const DriveSwitcherTrigger = buildDefaultTrigger(
  <LuChevronsUpDown />,
  'Switch Drive',
  SwitcherButton,
);

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
