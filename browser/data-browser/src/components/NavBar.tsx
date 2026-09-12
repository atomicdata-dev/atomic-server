import { styled, css } from 'styled-components';
import {
  useResource,
  useString,
  useTitle,
  useArray,
  useStore,
  useCanWrite,
  Resource,
  core,
  server,
  dataBrowser,
} from '@tomic/react';
import { constructOpenURL } from '../helpers/navigation';
import {
  useNavigateWithTransition,
  useBackForward,
} from '../hooks/useNavigateWithTransition';
import { useSettings } from '../helpers/AppSettings';
import { Button } from './Button';
import { BREADCRUMB_BAR_TRANSITION_TAG } from '../helpers/transitionName';
import { transition } from '../helpers/transition';
import { ResourceContextMenu } from './ResourceContextMenu';
import { ParentContextMenuTrigger } from './ResourceContextMenu/ParentContextMenuTrigger';
import {
  FaArrowLeft,
  FaArrowRight,
  FaBars,
  FaComments,
  FaMagnifyingGlass,
  FaShare,
  FaTags,
} from 'react-icons/fa6';
import * as RadixPopover from '@radix-ui/react-popover';
import type { JSX } from 'react';
import {
  useState,
  useEffect,
  useMemo,
  useRef,
  useCallback,
  useLayoutEffect,
} from 'react';
import { useAISidebar } from './AI/AISidebarContext';
import { useRightPanel } from './RightPanel/RightPanelContext';
import { LabelButton } from './NavBarButton';
import { useCommentCount } from '../hooks/useCommentCount';
import { AIIcon } from './AI/AIIcon';
import { useAISettings } from './AI/AISettingsContext';
import { TagSelectPopover } from './Tag/TagSelectPopover';
import { Tag } from './Tag/Tag';
import { getResourcesDrive } from '@helpers/getResourcesDrive';
import { ShareDialog } from './Share/ShareDialog';
import { IconButton } from './IconButton/IconButton';
import { displayShortcut, shortcuts } from './HotKeyWrapper';
import { useMediaQuery } from '../hooks/useMediaQuery';
import { isRunningInTauri } from '../helpers/tauri';
import { openSearchOverlay } from './OverlayContainer';
import { useAIChanges } from './AIChangesContext';
import { Row } from './Row';
import { ContentLanguageSelect } from './ContentLanguageSelect';
import { ResourcePresenceRow } from './Presence/ResourcePresenceRow';
import { FollowStatus } from './Presence/FollowStatus';
import { MeetingBanner } from './Presence/MeetingBanner';

export type NavBarProps = {
  resource?: Resource;
};

/** Tag select popover wrapper - needs to be separate component to use hooks */
function TagSelectPopoverWrapper({ resource }: { resource: Resource }) {
  const store = useStore();
  const [driveSubject, setDriveSubject] = useState<string>();
  const drive = useResource(driveSubject);
  const [driveTags, , pushDriveTags] = useArray(
    drive,
    dataBrowser.properties.tagList,
    { commit: true },
  );
  const [tags, setTags] = useArray(resource, dataBrowser.properties.tags, {
    commit: true,
  });
  const canCreateTags = useCanWrite(drive);

  useEffect(() => {
    getResourcesDrive(resource, store).then(setDriveSubject);
  }, [resource, store]);

  const handleNewTag = (newTag: string) => {
    // Tag creation finishes asynchronously; append to the live resource
    // instead of replacing it with the array captured by an older render.
    pushDriveTags([newTag]);
  };

  if (driveSubject === undefined || resource.loading) {
    return (
      <LabelButton disabled>
        <FaTags />
        <span>Tags</span>
      </LabelButton>
    );
  }

  return (
    <>
      <TagSelectPopover
        tags={driveTags}
        selectedTags={tags}
        setSelectedTags={setTags}
        onNewTag={canCreateTags ? handleNewTag : undefined}
        newTagParent={canCreateTags ? driveSubject : undefined}
        Trigger={
          <LabelButton
            as={RadixPopover.Trigger}
            data-testid='navbar-tags-button'
          >
            <FaTags />
            <span>Tags</span>
            {tags.length > 0 && <TagsCount>+{tags.length}</TagsCount>}
          </LabelButton>
        }
      />
      {tags.length > 0 && (
        <InlineTagsRow>
          {tags.map(t => (
            <TagPageLink key={t} subject={t} />
          ))}
        </InlineTagsRow>
      )}
    </>
  );
}

/** Shows a "Set drive" button if the current drive is different from the Subject */
function DriveMismatch({ subject }: { subject: string }) {
  const { drive, setDrive } = useSettings();
  const resource = useResource(subject, { allowIncomplete: true });
  const [title] = useTitle(resource);
  const classes = resource.getClasses();

  const handleSetDrive = () => {
    setDrive(subject);
  };

  const mismatch = subject && subject !== drive;

  if (mismatch && classes[0] === server.classes.drive) {
    return (
      <Button
        title={`Set ${title} as current drive`}
        subtle
        onClick={handleSetDrive}
      >
        Set Drive
      </Button>
    );
  }

  return null;
}

/** Direct parent breadcrumb only. Hidden if the parent is unauthorized. */
function DirectParent({ subject }: { subject: string }): JSX.Element | null {
  const resource = useResource(subject, { allowIncomplete: true });
  const [title] = useTitle(resource);
  const navigate = useNavigateWithTransition();

  if (resource.error || resource.isUnauthorized()) {
    return null;
  }

  const handleClick: React.MouseEventHandler<HTMLAnchorElement> = e => {
    e.preventDefault();
    navigate(constructOpenURL(subject));
  };

  return (
    <>
      <DriveMismatch subject={subject} />
      <Breadcrumb href={subject} onClick={handleClick}>
        {title}
      </Breadcrumb>
      <Divider>/</Divider>
    </>
  );
}

/** A tag chip that links to the tag's page */
function TagPageLink({ subject }: { subject: string }): JSX.Element {
  const navigate = useNavigateWithTransition();

  const handleClick: React.MouseEventHandler<HTMLAnchorElement> = e => {
    e.preventDefault();
    navigate(constructOpenURL(subject));
  };

  return (
    <TagAnchor href={constructOpenURL(subject)} onClick={handleClick}>
      <Tag subject={subject} />
    </TagAnchor>
  );
}

/** Breadcrumb list and actions bar */
export function NavBar({ resource: resourceProp }: NavBarProps): JSX.Element {
  const { drive, sideBarLocked, setSideBarLocked } = useSettings();
  const driveResource = useResource(drive);

  /**
   * The resource the user is actually looking at, if any. App routes
   * (/app/settings, /app/sync, …) are pages of the app itself, not of a
   * resource, so they have no subject.
   */
  const contextResource =
    resourceProp &&
    resourceProp.subject &&
    resourceProp.subject !== 'unknown-subject'
      ? resourceProp
      : undefined;

  /** Falls back to the drive so the breadcrumb still names where you are. */
  const resource = contextResource ?? driveResource;

  const [parent] = useString(resource, core.properties.parent);
  const { changes, revertResource, acceptChanges } = useAIChanges();
  const { enableAI } = useAISettings();
  const { isOpen: aiOpen, setIsOpen } = useAISidebar();
  const hasAiChanges = !!contextResource && changes.includes(resource.subject);

  const handleAcceptChanges = async () => {
    acceptChanges(resource);
  };

  const { back, forward } = useBackForward();
  const [title] = useTitle(resource);

  const machesStandalone = useMediaQuery(
    '(display-mode: standalone) or (display-mode: fullscreen)',
  );

  const isInStandaloneMode = useMemo<boolean>(
    () =>
      machesStandalone ||
      // @ts-expect-error standalone is available on the navigator object.
      window.navigator.standalone ||
      document.referrer.includes('android-app://') ||
      isRunningInTauri(),
    [machesStandalone],
  );

  // Collapse the action buttons to icons only when the bar's content no longer
  // fits — content-aware rather than a fixed px breakpoint. `collapseWidthRef`
  // remembers the width at which labels last overflowed and only re-expands
  // clearly above it, so it settles instead of flip-flopping at the boundary.
  const navRef = useRef<HTMLElement>(null);
  const collapseWidthRef = useRef(0);
  const [iconOnly, setIconOnly] = useState(false);

  const measureNav = useCallback(() => {
    const nav = navRef.current;

    if (!nav) return;

    const width = nav.clientWidth;
    const overflowing = nav.scrollWidth > width + 1;

    setIconOnly(prev => {
      if (overflowing) {
        collapseWidthRef.current = Math.max(collapseWidthRef.current, width);

        return true;
      }

      // Room again: expand only once clearly wider than where it collapsed.
      if (prev && width > collapseWidthRef.current + 24) {
        return false;
      }

      return prev;
    });
  }, []);

  useLayoutEffect(() => {
    const nav = navRef.current;

    if (!nav) return;

    const observer = new ResizeObserver(() => measureNav());
    observer.observe(nav);
    measureNav();

    return () => observer.disconnect();
  }, [measureNav]);

  // A new title may fit with labels again — forget the learned threshold so it
  // can re-expand.
  useLayoutEffect(() => {
    collapseWidthRef.current = 0;
  }, [title]);

  // Re-measure after the mode flips (the label change resizes the content but
  // not the bar, so the observer won't fire on its own) or the title changes.
  useLayoutEffect(() => {
    measureNav();
  }, [iconOnly, title, measureNav]);

  return (
    <NavBarWrapper ref={navRef} aria-label='Breadcrumbs'>
      <NavIconButton
        color='textLight'
        type='button'
        onClick={() => setSideBarLocked(!sideBarLocked)}
        title={`Show / hide sidebar (${displayShortcut(shortcuts.sidebarToggle)})`}
        data-test='sidebar-toggle'
      >
        <FaBars />
      </NavIconButton>
      {isInStandaloneMode && (
        <WideOnly>
          <NavIconButton
            color='textLight'
            type='button'
            title='Go back'
            onClick={back}
          >
            <FaArrowLeft />
          </NavIconButton>
          <NavIconButton
            color='textLight'
            type='button'
            title='Go forward'
            onClick={forward}
          >
            <FaArrowRight />
          </NavIconButton>
        </WideOnly>
      )}
      <NavIconButton
        color='textLight'
        type='button'
        title={`Search (${shortcuts.search})`}
        onClick={() => openSearchOverlay()}
      >
        <FaMagnifyingGlass />
      </NavIconButton>
      <VerticalDivider />
      <CrumbGroup $iconOnly={iconOnly}>
        {parent && <DirectParent subject={parent} />}
        <EditableBreadcrumb resource={resource} fallback={title} />
      </CrumbGroup>
      <Spacer />
      <ButtonArea $iconOnly={iconOnly}>
        <FollowStatus />
        <MeetingBanner />
        <ContentLanguageSelect />
        {/* Everything below acts on the resource you're looking at, so it only
         * makes sense when there is one. */}
        {contextResource && (
          <>
            <ResourcePresenceRow subject={contextResource.subject} />
            {hasAiChanges && (
              <Row gap='0.5rem' center>
                <SmallButton
                  clean
                  onClick={() => revertResource(contextResource.subject)}
                >
                  Revert
                </SmallButton>
                <SmallButton onClick={handleAcceptChanges}>
                  Accept Changes
                </SmallButton>
              </Row>
            )}
            <CommentsButton subject={contextResource.subject} />
            {enableAI && (
              <LabelButton
                $active={aiOpen}
                onClick={() => setIsOpen(prev => !prev)}
              >
                <AIIcon />
                <span>AI</span>
              </LabelButton>
            )}
            <TagSelectPopoverWrapper resource={contextResource} />
            <ShareDialog
              subject={contextResource.subject}
              trigger={
                <LabelButton as='button'>
                  <FaShare />
                  <span>Share</span>
                </LabelButton>
              }
            />
            <ResourceContextMenu
              isMainMenu
              subject={contextResource.subject}
              trigger={ParentContextMenuTrigger}
            />
          </>
        )}
      </ButtonArea>
    </NavBarWrapper>
  );
}

/** Comments panel toggle showing the live comment count at the icon. */
function CommentsButton({ subject }: { subject: string }): JSX.Element {
  const { togglePanel, activePanel } = useRightPanel();
  const { count, hasUnseen } = useCommentCount(subject);

  return (
    <CommentsLabelButton
      $active={activePanel === 'comments'}
      onClick={() => togglePanel('comments')}
      data-testid='navbar-comments-button'
      data-unseen={hasUnseen ? '' : undefined}
      title={
        count > 0
          ? /* @wc-ignore */ `${count} comments`
          : /* @wc-ignore */ 'Comments'
      }
    >
      {count > 0 ? <CommentCount>{count}</CommentCount> : <FaComments />}
      <span>Comments</span>
    </CommentsLabelButton>
  );
}

const NavBarWrapper = styled.nav`
  height: 100%;
  width: 100%;
  padding-inline: ${p => p.theme.size(1)};
  display: flex;
  flex-direction: row;
  align-items: center;
  justify-content: flex-start;

  view-transition-name: ${BREADCRUMB_BAR_TRANSITION_TAG};

  container: breadcrumb-bar / inline-size;

  @media print {
    display: none;
  }
`;

/**
 * The bar's plain icon buttons (sidebar, back/forward, search, up). Darkens on
 * hover like {@link LabelButton} so left and right feel like one set.
 */
const NavIconButton = styled(IconButton)`
  &:not([disabled]) {
    &:hover,
    &:focus-visible {
      color: ${p => p.theme.colors.text};
    }
  }
`;

const VerticalDivider = styled.div`
  width: 1px;
  background-color: ${props => props.theme.colors.bg2};
  height: 1.5rem;
  margin-inline: ${p => p.theme.size(1)};
`;

const Spacer = styled.span`
  flex: 1;
`;

/**
 * Holds the parent + current-page breadcrumb. While labels are shown it keeps
 * its natural width (`flex-shrink: 0`) so the bar genuinely overflows once the
 * buttons no longer fit — that overflow is what triggers icon-only mode. Once
 * collapsed it may shrink and truncate as a last resort, so the breadcrumb
 * gives way only after the labels are gone.
 */
const CrumbGroup = styled.div<{ $iconOnly: boolean }>`
  display: flex;
  align-items: center;
  min-width: 0;
  overflow: hidden;
  flex-shrink: ${p => (p.$iconOnly ? 1 : 0)};

  /* Narrow bars drop the trail: the sidebar and the OS back gesture cover
     navigation, and the title is right below the bar. */
  @container breadcrumb-bar (max-width: 600px) {
    display: none;
  }
`;

/**
 * In-app back/forward only earn their space on wide bars — on mobile the OS
 * provides these as gestures.
 */
const WideOnly = styled.span`
  display: contents;

  @container breadcrumb-bar (max-width: 600px) {
    display: none;
  }
`;

const ButtonArea = styled.div<{ $iconOnly: boolean }>`
  display: flex;
  margin-left: auto;
  color: ${p => p.theme.colors.textLight};
  gap: ${p => p.theme.size(1)};
  align-items: center;
  flex-shrink: 0;

  @container breadcrumb-bar (max-width: 600px) {
    gap: 0;
  }

  /* Icon-only once the bar can no longer fit the labels (measured in JS, not a
   * fixed breakpoint). */
  ${p =>
    p.$iconOnly &&
    css`
      & > * > span {
        display: none;
      }
    `}
`;

const CommentsLabelButton = styled(LabelButton)`
  &[data-unseen] {
    color: ${p => p.theme.colors.main};
    font-weight: bold;
  }
`;

/**
 * Rendered in place of the comment icon, matching its 1em footprint so the
 * navbar doesn't shift. Uses <b>: ButtonArea's icon-only rule hides <span>s
 * on narrow screens, but the count must stay visible.
 */
const CommentCount = styled.b`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 1em;
  font-weight: inherit;
  line-height: 1;
`;

/** Tag chips row — visible on wide, hidden on narrow */
const InlineTagsRow = styled.span`
  display: inline-flex;
  align-items: center;
  gap: 0.4ch;
  font-size: 0.75rem;

  @container breadcrumb-bar (max-width: 600px) {
    display: none;
  }
`;

const TagAnchor = styled.a`
  text-decoration: none;
  display: contents;
`;

/** "+N" badge inside the Tags button — uses <b> to avoid ButtonArea's span-hiding rule */
const TagsCount = styled.b`
  font-weight: inherit;
  font-size: 0.75em;
  opacity: 0.7;

  @container breadcrumb-bar (min-width: 601px) {
    display: none;
  }
`;

const Divider = styled.div`
  padding: 0.1rem 0.2rem;
`;

const BreadCrumbBase = css`
  font-size: ${props => props.theme.fontSizeBody}rem;
  font-family: ${props => props.theme.fontFamily};
  padding: 0.1rem 0.5rem;
  color: ${p => p.theme.colors.textLight};
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 0;
  ${transition('background-color', 'color')}
`;

const BreadCrumbCurrent = styled.span<{ $editable?: boolean }>`
  ${BreadCrumbBase}
  border-radius: ${p => p.theme.radius};
  cursor: ${p => (p.$editable ? 'text' : 'default')};

  ${p =>
    p.$editable &&
    css`
      &:hover {
        background: ${p.theme.colors.bg1};
        color: ${p.theme.colors.text};
      }
    `}
`;

const BreadCrumbInput = styled.input`
  ${BreadCrumbBase}
  color: ${p => p.theme.colors.text};
  background: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  outline: none;
  min-width: 12ch;

  &:focus {
    border-color: ${p => p.theme.colors.main};
  }
`;

/**
 * The current-page breadcrumb, rendered as a click-to-rename inline
 * editor. Mirrors {@link EditableTitle} (commit on Enter / blur, Escape
 * cancels) but stays small enough to live in the breadcrumb row. Falls
 * back to read-only display if the user lacks write permission, or if
 * the resource is unsaved.
 */
function EditableBreadcrumb({
  resource,
  fallback,
}: {
  resource: Resource;
  fallback: string;
}): JSX.Element {
  const [text, setText] = useTitle(resource, Infinity, {
    commit: true,
    validate: false,
  });
  const canEdit = useCanWrite(resource);
  const [isEditing, setIsEditing] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isEditing) {
      inputRef.current?.focus();
      inputRef.current?.select();
    }
  }, [isEditing]);

  const display = text || fallback;

  if (isEditing && canEdit) {
    return (
      <BreadCrumbInput
        ref={inputRef}
        type='text'
        value={text || ''}
        placeholder='Untitled'
        onChange={e => setText(e.target.value)}
        onBlur={() => setIsEditing(false)}
        onKeyDown={e => {
          if (e.key === 'Enter') {
            e.preventDefault();
            setIsEditing(false);
          } else if (e.key === 'Escape') {
            setIsEditing(false);
          }
        }}
      />
    );
  }

  return (
    <BreadCrumbCurrent
      $editable={!!canEdit}
      title={canEdit ? 'Click to rename' : undefined}
      onClick={() => {
        if (canEdit) setIsEditing(true);
      }}
    >
      {display}
    </BreadCrumbCurrent>
  );
}

const Breadcrumb = styled.a`
  ${BreadCrumbBase}
  align-self: center;
  cursor: pointer;
  text-decoration: none;
  border-radius: ${p => p.theme.radius};

  &:hover {
    background: ${p => p.theme.colors.bg1};
    color: ${p => p.theme.colors.text};
  }

  &:active {
    background: ${p => p.theme.colors.bg2};
  }
`;

const SmallButton = styled(Button)`
  font-size: 0.7rem;
  padding: 0.1rem 0.5rem;
  height: 1.5rem;
`;

export default NavBar;
