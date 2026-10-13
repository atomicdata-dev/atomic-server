import { styled } from 'styled-components';
import * as React from 'react';
import { useHover } from '../../helpers/useHover';
import { useSettings } from '../../helpers/AppSettings';
import { SideBarDrive } from './SideBarDrive';
import { DndContext, DragOverlay } from '@dnd-kit/core';
import { createPortal } from 'react-dom';
import { SidebarDropZones } from './SidebarDropZones';
import { SidebarItemTitle } from './ResourceSideBar/SidebarItemTitle';
import { sidebarCollisionDetection, useSidebarDnd } from './useSidebarDnd';
import {
  DragAreaBase,
  responsiveWidth,
  useResizable,
} from '../../hooks/useResizable';
import { useCombineRefs } from '../../hooks/useCombineRefs';
import { AccountMenu } from './AccountMenu';
import { SideBarHomePanels } from './SideBarHomePanels';
import { useMediaQuery } from '../../hooks/useMediaQuery';
import { useSidebarSwipe } from '../../hooks/useSidebarSwipe';
import { useAndroidBack } from '../../helpers/androidBack';
import { Column } from '../Row';
import { OntologiesPanel } from './OntologySideBar/OntologiesPanel';
import { SideBarPanel } from './SideBarPanel';
import { Panel, usePanelList } from './usePanelList';
import { SIDEBAR_WIDTH_PROP } from './SidebarCSSVars';
import { useRef, type JSX } from 'react';
import { CalculatedPageHeight } from '../../globalCssVars';
import { AIChatsPanel } from './AIPanel';
import { ChromeTheme } from '../../styling';
import { PanelBackdrop, PanelLayout, panelTransition } from '../PanelLayout';
import { useRightPanel } from '../RightPanel/RightPanelContext';
import { RIGHT_PANEL_OVERLAY_BREAKPOINT } from '../RightPanel/layout';

/** Amount of pixels where the sidebar automatically shows */
export const SIDEBAR_TOGGLE_WIDTH = 600;

const SideBarDriveMemo = React.memo(SideBarDrive);

export function SideBar(): JSX.Element {
  const targetRef = useRef<HTMLDivElement>(null);

  const { drive, sideBarLocked, setSideBarLocked } = useSettings();
  const [isRearanging, setIsRearanging] = React.useState(false);
  const {
    handleDragStart,
    handleDragEnd,
    handleDragCancel,
    draggingResource,
    sensors,
    animateDrop,
    dndExplanation,
    announcements,
  } = useSidebarDnd(setIsRearanging);
  const { activePanel } = useRightPanel();
  const [ref, hoveringOverSideBar, listeners] = useHover<HTMLElement>();
  // Check if the window is small enough to hide the sidebar
  const isWideScreen = useMediaQuery(
    `(min-width: ${SIDEBAR_TOGGLE_WIDTH}px)`,
    true,
  );
  const rightPanelOverlays = useMediaQuery(
    `(max-width: ${RIGHT_PANEL_OVERLAY_BREAKPOINT - 1}px)`,
  );

  const { size, dragAreaRef, isDragging, dragAreaListeners } = useResizable({
    initialSize: responsiveWidth({ large: 300, laptop: 240 }),
    minSize: 200,
    maxSize: 2000,
    targetRef,
  });

  // Touch: swipe right (from the left part of the content, past the OS
  // back-gesture edge) opens/locks the sidebar; swipe left closes it. Not
  // gated on screen width — tablets are wide AND touch-first. Mouse/trackpad
  // input never emits touch events, so desktops are unaffected.
  useSidebarSwipe({
    enabled: true,
    open: sideBarLocked,
    onOpen: () => setSideBarLocked(true),
    onClose: () => setSideBarLocked(false),
  });

  // On a narrow screen the open sidebar is a drawer over the page, and back
  // closes it before it navigates.
  useAndroidBack(sideBarLocked && !isWideScreen, () => setSideBarLocked(false));

  const { enabledPanels } = usePanelList();

  const mountRefs = useCombineRefs([ref, targetRef]);

  /**
   * This is called when the user presses a menu Item, which should result in a
   * closed menu in mobile context
   */
  const closeSideBar = React.useCallback(() => {
    // If the window is small, close the sidebar on click
    if (!isWideScreen) {
      setSideBarLocked(false);
    }
  }, [isWideScreen, setSideBarLocked]);

  const sidebarVisible =
    sideBarLocked ||
    (hoveringOverSideBar &&
      isWideScreen &&
      !(rightPanelOverlays && activePanel));

  return (
    <SideBarContainer
      data-side-panel='left'
      $width={SIDEBAR_WIDTH_PROP.var()}
      $size={size}
      $expanded={isWideScreen && sideBarLocked}
      $dragging={isDragging}
    >
      <ChromeTheme>
        <StyledNav
          ref={mountRefs}
          data-testid='sidebar'
          locked={isWideScreen && sideBarLocked}
          exposed={sidebarVisible}
          $dragging={isDragging}
          {...listeners}
        >
          {/* The DndContext lives here so the tree (draggables, drop edges) and
              the Favorites / Trash zones (which take the panels' place while
              dragging) share one context. It renders no DOM of its own. */}
          <DndContext
            onDragStart={handleDragStart}
            onDragEnd={handleDragEnd}
            onDragCancel={handleDragCancel}
            sensors={sensors}
            // `closestCenter` lets the 3-pixel `DropEdge` strips between
            // siblings win over the much-taller "drop onto folder row"
            // targets when the dragged item is over a sibling gap. With the
            // default `rectIntersection` the bigger row always swallowed
            // every drop and inter-sibling reordering became unreachable. The
            // Favorites / Trash zones take priority while the pointer is on
            // them.
            collisionDetection={sidebarCollisionDetection}
            accessibility={{
              announcements,
              screenReaderInstructions: {
                draggable: dndExplanation,
              },
            }}
          >
            {/* The key is set to make sure the component is re-loaded when the baseURL changes */}
            <SideBarDriveMemo onItemClick={closeSideBar} key={drive} />
            {/* While dragging, the zones take the panels' spot. The panels are
                hidden (display: none), not unmounted, so their state and
                scroll position survive the drag. */}
            <SidebarDropZones draggingResource={draggingResource} />
            <MenuWrapper $hidden={!!draggingResource}>
              <Column gap='0.125rem' align='stretch'>
                <SideBarHomePanels onItemClick={closeSideBar} />
                {enabledPanels.has(Panel.AIChats) && (
                  <AIChatsPanel key={drive} />
                )}
                {enabledPanels.has(Panel.Ontologies) && (
                  <SideBarPanel
                    title='Ontologies'
                    panel={Panel.Ontologies}
                    heightStorageKey='ontologiesPanelHeight'
                    initialHeight={160}
                    key={drive}
                  >
                    <OntologiesPanel />
                  </SideBarPanel>
                )}
                <AccountMenu onItemClick={closeSideBar} />
              </Column>
            </MenuWrapper>
            {createPortal(
              <DragOverlay dropAnimation={animateDrop}>
                {draggingResource && (
                  <SidebarItemTitle
                    subject={draggingResource}
                    hideActionButtons
                    isDragging
                  />
                )}
              </DragOverlay>,
              document.body,
            )}
          </DndContext>
          {!isRearanging && (
            <SideBarDragArea
              ref={dragAreaRef}
              isDragging={isDragging}
              {...dragAreaListeners}
            />
          )}
        </StyledNav>
      </ChromeTheme>
      <SideBarOverlay
        onClick={() => setSideBarLocked(false)}
        $visible={sideBarLocked && !isWideScreen}
        aria-hidden
      />
    </SideBarContainer>
  );
}

interface StyledNavProps {
  locked: boolean;
  exposed: boolean;
  $dragging: boolean;
}

const StyledNav = styled.nav<StyledNavProps>`
  z-index: ${p => p.theme.zIndex.sidebar + 2};
  box-sizing: border-box;
  background: ${p => p.theme.colors.bg};
  transition: ${p => panelTransition(p.$dragging, 'transform', 'opacity')};
  left: 0;
  transform: ${p =>
    p.exposed ? 'translateX(0)' : 'translateX(calc(-100% + 0.5rem))'};
  opacity: ${p => (p.exposed ? 1 : 0)};
  height: ${CalculatedPageHeight.var()};
  width: ${SIDEBAR_WIDTH_PROP.var()};
  position: absolute;
  border-right: ${p => `1px solid ${p.theme.colors.bg2}`};
  box-shadow: ${p => (p.locked ? 'none' : p.theme.boxShadowSoft)};
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  overflow-x: hidden;
  padding-bottom: ${p => p.theme.size()};
`;

const MenuWrapper = styled.div<{ $hidden?: boolean }>`
  display: ${p => (p.$hidden ? 'none' : 'flex')};
  margin-top: auto;
  flex-direction: column;
  justify-items: flex-end;
  justify-content: end;
  box-sizing: border-box;
  width: 100%;
  min-width: 0;
  /* Same horizontal inset as drive {@link SideBarDrive} ListWrapper */
  padding-inline: ${p => p.theme.margin}rem;
`;

const SideBarContainer = styled(PanelLayout).attrs<{ $size: string }>(p => ({
  style: {
    [SIDEBAR_WIDTH_PROP.raw]: p.$size,
  } as Record<string, string>,
}))`
  @media print {
    display: none;
  }
`;

/** Shown on mobile devices to close the panel */
const SideBarOverlay = styled(PanelBackdrop)`
  z-index: ${p => p.theme.zIndex.sidebar + 1};
`;

const SideBarDragArea = styled(DragAreaBase)`
  --handle-margin: 1rem;
  height: calc(100% - var(--handle-margin) * 2);
  margin-top: var(--handle-margin);
  width: 12px;
  right: -6px;
  top: 0;
  bottom: 0;
`;
