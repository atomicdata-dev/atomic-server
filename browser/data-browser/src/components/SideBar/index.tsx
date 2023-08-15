import styled from 'styled-components';
import * as React from 'react';
import { useHover } from '../../helpers/useHover';
import { useSettings } from '../../helpers/AppSettings';
import { SideBarDrive } from './SideBarDrive';
import { DragAreaBase, useResizable } from '../../hooks/useResizable';
import { useCombineRefs } from '../../hooks/useCombineRefs';
import { NavBarSpacer } from '../NavBarSpacer';
import { AppMenu } from './AppMenu';
import { About } from './About';
import { useMediaQuery } from '../../hooks/useMediaQuery';

/** Amount of pixels where the sidebar automatically shows */
export const SIDEBAR_TOGGLE_WIDTH = 600;

const SideBarDriveMemo = React.memo(SideBarDrive);

export function SideBar(): JSX.Element {
  const { drive, sideBarLocked, setSideBarLocked } = useSettings();
  const [ref, hoveringOverSideBar, listeners] = useHover<HTMLElement>();
  // Check if the window is small enough to hide the sidebar
  const isWideScreen = useMediaQuery(
    `(min-width: ${SIDEBAR_TOGGLE_WIDTH}px)`,
    true,
  );

  const { size, targetRef, dragAreaRef, isDragging } = useResizable({
    initialSize: 300,
    minSize: 200,
    maxSize: 2000,
  });

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
  }, [isWideScreen]);

  const sidebarVisible = sideBarLocked || (hoveringOverSideBar && isWideScreen);

  return (
    <SideBarContainer>
      <SideBarStyled
        ref={mountRefs}
        size={size}
        data-test='sidebar'
        locked={isWideScreen && sideBarLocked}
        exposed={sidebarVisible}
        {...listeners}
      >
        <NavBarSpacer position='top' />
        {/* The key is set to make sure the component is re-loaded when the baseURL changes */}
        <SideBarDriveMemo handleClickItem={closeSideBar} key={drive} />
        <MenuWrapper>
          <AppMenu onItemClick={closeSideBar} />
          <About />
        </MenuWrapper>
        <NavBarSpacer baseMargin='1rem' position='bottom' />
        <SideBarDragArea ref={dragAreaRef} isDragging={isDragging} />
      </SideBarStyled>
      <SideBarOverlay
        onClick={() => setSideBarLocked(false)}
        visible={sideBarLocked && !isWideScreen}
      />
    </SideBarContainer>
  );
}

interface SideBarStyledProps {
  locked: boolean;
  exposed: boolean;
  size: string;
}

interface SideBarOverlayProps {
  visible: boolean;
}

// eslint-disable-next-line prettier/prettier
const SideBarStyled = styled('nav').attrs<SideBarStyledProps>(p => ({
  style: {
    '--width': p.size,
  },
}))<SideBarStyledProps>`
  z-index: ${p => p.theme.zIndex.sidebar};
  box-sizing: border-box;
  background: ${p => p.theme.colors.bg};
  transition: opacity 0.3s, left 0.3s;
  left: ${p => (p.exposed ? '0' : `calc(var(--width) * -1 + 0.5rem)`)};
  /* When the user is hovering, show half opacity */
  opacity: ${p => (p.exposed ? 1 : 0)};
  height: 100vh;
  width: var(--width);
  position: ${p => (p.locked ? 'relative' : 'absolute')};
  border-right: ${p => (p.locked ? 'none' : `1px solid ${p.theme.colors.bg2}`)};
  box-shadow: ${p => (p.locked ? 'none' : p.theme.boxShadowSoft)};
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  overflow-x: hidden;

  view-transition-name: sidebar;
`;

const MenuWrapper = styled.div`
  margin-top: auto;
  flex-direction: column;
  justify-items: flex-end;
  display: flex;
  justify-content: end;
`;

/** Just needed for positioning the overlay */
const SideBarContainer = styled('div')`
  position: relative;
`;

/** Shown on mobile devices to close the panel */
const SideBarOverlay = styled.div<SideBarOverlayProps>`
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  right: 0;
  width: 100vw;
  transition: background-color 0.2s;
  background-color: ${p =>
    p.visible ? 'rgba(0, 0, 0, .5)' : 'rgba(0, 0, 0, 0.0)'};
  pointer-events: ${p => (p.visible ? 'auto' : 'none')};
  height: 100%;
  cursor: pointer;
  z-index: 1;
  -webkit-tap-highlight-color: transparent;
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
