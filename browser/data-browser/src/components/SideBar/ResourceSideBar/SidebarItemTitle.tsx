import { websiteVersionName } from '@chunks/Website/websiteVersionName';
import { forwardRef, memo, useState } from 'react';
import { styled, css, keyframes } from 'styled-components';
import { SideBarItem } from '../SideBarItem';
import { FloatingActions, floatingHoverStyles } from './FloatingActions';
import { useResource, useTitle } from '@tomic/react';
import { ResourceGlyph } from '../../ResourceGlyph';
import { SyntheticListenerMap } from '@dnd-kit/core/dist/hooks/utilities';
import { DraggableAttributes } from '@dnd-kit/core';
import { StyledLink, TextWrapper } from './shared';
import {
  SIDEBAR_TRANSITION_TAG,
  getTransitionName,
} from '../../../helpers/transitionName';
import { useSettings } from '../../../helpers/AppSettings';
import { IconButton } from '../../IconButton/IconButton';
import { FaCaretRight, FaGripVertical } from 'react-icons/fa6';
import { SidebarPresence } from '../../Presence/SidebarPresence';

interface SidebarItemTitleProps {
  subject: string;
  active?: boolean;
  listeners?: SyntheticListenerMap;
  attributes?: DraggableAttributes;
  hideActionButtons?: boolean;
  isDragging?: boolean;
  onClick?: () => unknown;
  /** When true, expand caret is shown in the class-icon slot (Details summary has no separate caret). */
  expandable?: boolean;
  expanded?: boolean;
  /** Toggle folder open (separate from navigation link hover). */
  onToggleExpand?: () => void;
}

const NavResourceLink = styled(StyledLink)`
  display: flex;
  align-self: stretch;
  /* A held touch is ours (menu or drag): no native callout or selection. */
  -webkit-touch-callout: none;
  -webkit-user-select: none;
  user-select: none;
`;

export const SidebarItemTitle = memo(
  forwardRef<HTMLAnchorElement, SidebarItemTitleProps>(
    (
      {
        subject,
        active,
        listeners,
        attributes,
        hideActionButtons,
        isDragging,
        onClick,
        expandable = false,
        expanded = false,
        onToggleExpand,
      },
      ref,
    ): React.JSX.Element => {
      const resource = useResource(subject);
      const { sidebarKeyboardDndEnabled } = useSettings();
      // A resource's own icon image or emoji takes precedence over its
      // class icon (the precedence lives in ResourceGlyph).
      const glyph = (
        <GlyphSlot aria-hidden>
          <ResourceGlyph resource={resource} />
        </GlyphSlot>
      );
      // Reactive title via `useTitle` (subscribes to `name`/`shortname`/
      // `filename` LocalChange events through `useValue`'s
      // `useSyncExternalStore`). Reading the bare `resource.title` getter
      // here would render once at mount and never update — the row only
      // refreshed when navigation forced a top-down re-render, which is
      // the "title only updates when I click in the sidebar" symptom.
      const [storedTitle] = useTitle(resource);
      const title = websiteVersionName(storedTitle);

      // The context menu is only visible on hover or focus, so it mounts then.
      // Mounting one per row cost ~3 ms a render, on every row, every click.
      const [actionsArmed, setActionsArmed] = useState(false);
      const armActions = () => setActionsArmed(true);

      const expandLabel = expanded ? 'Collapse folder' : 'Expand folder';

      // An expandable row keeps its icon and wears the caret as a small
      // badge in its corner: always visible, so the row reads as a folder
      // without hovering it, and grown on hover.
      const expandControl = (
        <GlyphWithCaret>
          {glyph}
          <CaretBadge aria-hidden>
            <ExpandCaret $open={expanded} />
          </CaretBadge>
        </GlyphWithCaret>
      );

      return (
        <ActionWrapper
          isDragging={isDragging}
          onPointerEnter={armActions}
          onFocus={armActions}
          data-sidebar-id={getTransitionName(SIDEBAR_TRANSITION_TAG, subject)}
        >
          {sidebarKeyboardDndEnabled ? (
            expandable ? (
              <>
                <ExpandToggleButton
                  type='button'
                  aria-expanded={expanded}
                  aria-label={expandLabel}
                  title={`Rearrange ${title}`}
                  onClick={e => {
                    e.preventDefault();
                    e.stopPropagation();
                    onToggleExpand?.();
                  }}
                  {...(listeners ?? {})}
                  {...(attributes ?? {})}
                >
                  {expandControl}
                </ExpandToggleButton>
                <RowBody>
                  <NavResourceLink subject={subject} clean ref={ref}>
                    <ResourceLinkSideBarItem
                      onClick={onClick}
                      disabled={active}
                      resource={subject}
                    >
                      <TextWrapper>
                        <TreeRowTitle>{title}</TreeRowTitle>
                        <SidebarPresence subject={subject} />
                      </TextWrapper>
                    </ResourceLinkSideBarItem>
                  </NavResourceLink>
                </RowBody>
              </>
            ) : (
              <NavResourceLink subject={subject} clean ref={ref}>
                <ResourceTreeRow
                  onClick={onClick}
                  disabled={active}
                  resource={subject}
                >
                  <TextWrapper>
                    <StyledIconButton
                      title={`Rearange ${title}`}
                      {...(listeners ?? {})}
                      {...(attributes ?? {})}
                      role='link'
                    >
                      {glyph}
                      <FaGripVertical />
                    </StyledIconButton>
                    <TreeRowTitle>{title}</TreeRowTitle>
                    <SidebarPresence subject={subject} />
                  </TextWrapper>
                </ResourceTreeRow>
              </NavResourceLink>
            )
          ) : expandable ? (
            <>
              <ExpandToggleButton
                type='button'
                aria-expanded={expanded}
                aria-label={expandLabel}
                title={expandLabel}
                onClick={e => {
                  e.preventDefault();
                  e.stopPropagation();
                  onToggleExpand?.();
                }}
              >
                {expandControl}
              </ExpandToggleButton>
              <RowBody>
                <NavResourceLink
                  subject={subject}
                  clean
                  ref={ref}
                  {...(listeners ?? {})}
                  {...(attributes ?? {})}
                >
                  <ResourceLinkSideBarItem
                    onClick={onClick}
                    disabled={active}
                    resource={subject}
                  >
                    <TextWrapper>
                      <TreeRowTitle>{title}</TreeRowTitle>
                      <SidebarPresence subject={subject} />
                    </TextWrapper>
                  </ResourceLinkSideBarItem>
                </NavResourceLink>
              </RowBody>
            </>
          ) : (
            <NavResourceLink
              subject={subject}
              clean
              ref={ref}
              {...(listeners ?? {})}
              {...(attributes ?? {})}
            >
              <ResourceTreeRow
                onClick={onClick}
                disabled={active}
                resource={subject}
              >
                <TextWrapper>
                  <LeadingSlot>{glyph}</LeadingSlot>
                  <TreeRowTitle>{title}</TreeRowTitle>
                  <SidebarPresence subject={subject} />
                </TextWrapper>
              </ResourceTreeRow>
            </NavResourceLink>
          )}
          {!hideActionButtons && (
            <FloatingActionsCell>
              <FloatingActions subject={subject} armed={actionsArmed} />
            </FloatingActionsCell>
          )}
        </ActionWrapper>
      );
    },
  ),
);

SidebarItemTitle.displayName = 'SidebarItemTitle';

const lift = keyframes`
  from {
    box-shadow: var(--aw-box-shadow-start);
    scale: 0.9;
  } to {
    box-shadow: var(--aw-box-shadow-end);
    scale: 1;
  }
`;

const StyledIconButton = styled(IconButton)`
  --button-padding: 0;
`;

/** Wraps the resource glyph; sized to line up with the svg class icons. */
const GlyphSlot = styled.span`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 0.9rem;
  line-height: 1;
`;

/** Same width as expand control so class icons line up with carets. */
const LeadingSlot = styled.span`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 1.5rem;
`;

const TreeRowTitle = styled.span`
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

/** Same box model as {@link SideBarItem}: padded cell for the 1.5rem leading slot. */
const ExpandToggleButton = styled.button`
  box-sizing: border-box;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  min-height: ${p => p.theme.margin * 0.5 + 1}rem;
  width: calc(1.5rem + 0.4rem);
  margin: 0;
  padding: 0.2rem;
  border: none;
  border-radius: ${p => p.theme.radius};
  background: transparent;
  cursor: pointer;
  color: ${p => p.theme.colors.main};

  &:hover {
    background-color: ${p => p.theme.colors.bg1};
  }

  &:active {
    background-color: ${p => p.theme.colors.bg2};
  }

  &:focus-visible {
    outline: 2px solid ${p => p.theme.colors.main};
    outline-offset: 1px;
  }
`;

const ExpandCaret = styled(FaCaretRight)<{ $open: boolean }>`
  flex-shrink: 0;
  transition: transform ${p => p.theme.animation.duration} ease-in-out;
  transform: rotate(${p => (p.$open ? '90deg' : '0deg')});
  font-size: 0.8rem;
`;

const GlyphWithCaret = styled.span`
  position: relative;
  color: ${p => p.theme.colors.textLight};
  display: inline-flex;
  align-items: center;
  justify-content: center;
`;

/** The caret on a row's icon: a small disc in its bottom-right corner. */
const CaretBadge = styled.span`
  position: absolute;
  right: -0.3rem;
  bottom: -0.25rem;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 0.7rem;
  height: 0.7rem;
  border-radius: 50%;
  background-color: ${p => p.theme.colors.bg};
  transform-origin: center;
  transition: transform ${p => p.theme.animation.duration} ease-out;
  pointer-events: none;
  color: ${p => p.theme.colors.main};

  ${ExpandCaret} {
    font-size: 0.55rem;
  }
`;

const RowBody = styled.div`
  flex: 1;
  min-width: 0;
  display: flex;
  align-items: stretch;
`;

/** Fills {@link RowBody} so hover/background spans the sidebar (minus caret + actions). */
const ResourceTreeRow = styled(SideBarItem)`
  flex: 1;
  min-width: 0;
  width: 100%;
  box-sizing: border-box;
  align-self: stretch;
`;

const ResourceLinkSideBarItem = ResourceTreeRow;

const FloatingActionsCell = styled.span`
  align-self: center;
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
`;

const ActionWrapper = styled.div<{ isDragging?: boolean }>`
  --aw-box-shadow-start: 0 0 0 0px rgba(0, 0, 0, 0.1);
  --aw-box-shadow-end:
    0 0 0 1px ${p => p.theme.colors.main}, ${p => p.theme.boxShadowSoft};

  box-sizing: border-box;
  display: flex;
  align-items: stretch;
  width: 100%;
  min-width: 0;
  gap: 0;
  ${floatingHoverStyles}
  border-radius: ${p => p.theme.radius};
  ${p =>
    p.isDragging &&
    css`
      animation: ${lift} 0.2s ease-in-out forwards;
      opacity: 0.9;
    `}

  ${StyledIconButton} svg:last-of-type {
    display: none;
    visibility: hidden;
  }

  &:focus-within,
  &:hover {
    ${StyledIconButton} svg:first-of-type {
      display: none;
      visibility: hidden;
    }
    ${StyledIconButton} svg:last-of-type {
      display: block;
      visibility: visible;
      cursor: grab;
    }
    /* The glyph (emoji / icon image / class icon, wrapped in GlyphSlot)
       makes way for the drag grip on hover (the svg swap rules above
       only match direct svg children). */
    ${StyledIconButton} ${GlyphSlot} {
      display: none;
    }
    ${CaretBadge} {
      transform: scale(1.35);
    }
  }

  ${ExpandToggleButton}:hover ${CaretBadge} {
    transform: scale(1.6);
  }
`;
