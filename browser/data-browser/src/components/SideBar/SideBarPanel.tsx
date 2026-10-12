import { styled } from 'styled-components';
import { FaChevronDown } from 'react-icons/fa6';
import { Collapse } from '../Collapse';
import { useRef, useState, type JSX } from 'react';
import { useResizable } from '@hooks/useResizable';
import { useLocalStorage } from '@hooks/useLocalStorage';
import { useLongPress } from '@hooks/useLongPress';
import { FaEyeSlash } from 'react-icons/fa6';
import { DropdownMenu } from '../Dropdown';
import { AutoOpenTrigger } from '../Dropdown/AutoOpenTrigger';
import { Panel, usePanelList } from './usePanelList';
import { SIDEBAR_BAR_HEIGHT, SIDEBAR_BAR_HEIGHT_TOUCH } from './SidebarCSSVars';

/** Height of one row in a sidebar section; anything shorter shows nothing. */
const ROW_HEIGHT = 32;
const MAX_HEIGHT = 1200;
/** Movement before a press on the header becomes a drag, not a click. */
const DRAG_THRESHOLD = 6;

export interface SideBarPanelProps {
  title: string;
  /** Stable, untranslated key for the section's height preference. */
  heightStorageKey: string;
  initialHeight?: number;
  actions?: React.ReactNode;
  /** When false, section starts collapsed */
  defaultOpen?: boolean;
  /** When set, a context menu on the header offers to hide this panel. */
  panel?: Panel;
  /** Tighter padding when nested inside the drive tree (e.g. Shared with me) */
  embedded?: boolean;
  'data-testid'?: string;
}

export function SideBarPanel({
  children,
  title,
  heightStorageKey,
  initialHeight = 320,
  actions,
  defaultOpen = true,
  embedded = false,
  panel,
  'data-testid': dataTestId,
}: React.PropsWithChildren<SideBarPanelProps>): JSX.Element {
  const [open, setOpen] = useLocalStorage(
    `${heightStorageKey}.open`,
    defaultOpen,
  );
  const contentRef = useRef<HTMLDivElement>(null);
  // The last height a drag ended at that showed at least one row. Ending a
  // drag below that is a request to close the section; opening it again comes
  // back at this height.
  const [storedHeight, setStoredHeight] = useLocalStorage(
    heightStorageKey,
    initialHeight,
  );
  const { size, dragAreaListeners, isDragging, setSize } = useResizable({
    initialSize: storedHeight,
    // Free all the way down: the old 60px floor (two rows) left no way to
    // shrink a section away short of the header's toggle.
    minSize: 0,
    maxSize: MAX_HEIGHT,
    targetRef: contentRef,
    edge: 'bottom',
    mode: 'delta',
    threshold: DRAG_THRESHOLD,
    // Remembered when a drag ends, so a drag that ends in a close keeps the
    // height the section had before it.
    onResizeEnd: height => {
      if (height >= ROW_HEIGHT) {
        setStoredHeight(height);

        return;
      }

      // Close from where the drag left it; the height to reopen at is set
      // when the section opens again.
      setOpen(false);
    },
  });

  // Dragging a closed section's header opens it and follows the pointer, the
  // same gesture as resizing an open one: up is taller.
  const [openingDrag, setOpeningDrag] = useState(false);
  const suppressToggle = useRef(false);

  const startOpeningDrag = (event: React.PointerEvent<HTMLElement>) => {
    if (event.button !== 0 || event.isPrimary === false) return;
    const startY = event.clientY;
    let opened = false;
    let height = 0;

    const move = (e: PointerEvent) => {
      const grow = startY - e.clientY;
      if (!opened && grow < DRAG_THRESHOLD) return;

      if (!opened) {
        opened = true;
        suppressToggle.current = true;
        setOpeningDrag(true);
        setSize(0);
        setOpen(true);
      }

      height = Math.min(MAX_HEIGHT, Math.max(0, grow));
      setSize(height);
    };

    const end = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', end);
      window.removeEventListener('pointercancel', end);
      if (!opened) return;
      setOpeningDrag(false);

      if (height >= ROW_HEIGHT) {
        setStoredHeight(height);
      } else {
        setOpen(false);
      }
    };

    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', end);
    window.addEventListener('pointercancel', end);
  };

  const { disablePanel } = usePanelList();
  const [menuPoint, setMenuPoint] = useState<{ x: number; y: number }>();
  const longPress = useLongPress(setMenuPoint);

  const toggle = () => {
    if (suppressToggle.current) {
      suppressToggle.current = false;

      return;
    }

    if (!open) setSize(storedHeight);
    setOpen(!open);
  };

  return (
    <Wrapper $embedded={embedded} data-testid={dataTestId}>
      <HeaderRow>
        <HeaderButton
          type='button'
          onClick={toggle}
          aria-expanded={open}
          aria-label={`${open ? 'Collapse' : 'Expand'} ${title}`}
          title={open ? 'Drag to resize' : 'Click or drag to open'}
          $dragging={isDragging || openingDrag}
          onPointerDown={e => {
            if (panel) longPress.handlers.onPointerDown(e);
            (open ? dragAreaListeners.onPointerDown : startOpeningDrag)?.(e);
          }}
          onPointerMove={panel ? longPress.handlers.onPointerMove : undefined}
          onPointerUp={panel ? longPress.handlers.onPointerUp : undefined}
          onPointerCancel={
            panel ? longPress.handlers.onPointerCancel : undefined
          }
          onContextMenu={
            panel
              ? e => {
                  e.preventDefault();
                  setMenuPoint({ x: e.clientX, y: e.clientY });
                }
              : undefined
          }
          // Always attached: a drag that closes the section re-renders it
          // closed before the click that ends the drag arrives, and that
          // click must not open it straight back up.
          onClickCapture={e => {
            if (panel && longPress.consumeClick()) {
              e.preventDefault();
              e.stopPropagation();

              return;
            }

            dragAreaListeners.onClickCapture?.(e);
          }}
        >
          <PanelTitle>{title}</PanelTitle>
          <Caret
            aria-hidden
            $open={open}
            $dragging={isDragging || openingDrag}
          />
        </HeaderButton>
        {actions}
      </HeaderRow>
      {panel && menuPoint && (
        <DropdownMenu
          Trigger={AutoOpenTrigger}
          searchable={false}
          anchorPoint={menuPoint}
          bindActive={active => !active && setMenuPoint(undefined)}
          items={[
            {
              id: 'hide-panel',
              label: `Hide ${title}`,
              icon: <FaEyeSlash />,
              onClick: () => disablePanel(panel),
            },
          ]}
        />
      )}
      <StyledCollapse open={open} $embedded={embedded} $instant={openingDrag}>
        <PanelContent ref={contentRef} style={{ maxHeight: size }}>
          {children}
        </PanelContent>
      </StyledCollapse>
    </Wrapper>
  );
}

const HeaderRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.25rem;
  min-height: ${SIDEBAR_BAR_HEIGHT};

  @media (pointer: coarse) {
    min-height: ${SIDEBAR_BAR_HEIGHT_TOUCH};
  }
`;

const PanelTitle = styled.span`
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: ${p => p.theme.colors.textLight};
  text-align: start;
  white-space: nowrap;
`;

/** Shows the section can fold: points down while open, right while closed. */
const Caret = styled(FaChevronDown)<{ $open: boolean; $dragging: boolean }>`
  margin-left: auto;
  flex-shrink: 0;
  font-size: 0.65rem;
  color: ${p => p.theme.colors.textLight};
  opacity: ${p => (p.$dragging ? 1 : 0)};
  transform: rotate(${p => (p.$open ? 0 : -90)}deg);
  transition:
    transform 150ms ease,
    opacity 150ms ease;
`;

const HeaderButton = styled.button<{ $dragging: boolean }>`
  background: none;
  border: none;
  margin: 0;
  padding: 0.35rem 0.5rem;
  display: flex;
  align-items: center;
  justify-content: flex-start;
  cursor: pointer;
  border-radius: ${p => p.theme.radius};
  box-sizing: border-box;
  width: 100%;
  text-align: start;
  gap: 0.5rem;

  &[aria-expanded='true'] {
    touch-action: none;
    user-select: none;
    cursor: row-resize;
  }

  &:hover ${Caret}, &:focus-visible ${Caret} {
    opacity: 1;
  }

  /* Callout and text selection would fight the long-press menu. */
  -webkit-touch-callout: none;
  user-select: none;
  align-self: stretch;

  @media (pointer: coarse) {
    ${Caret} {
      opacity: 0.5;
    }
  }

  &:hover {
    background-color: ${p => p.theme.colors.bg1};
  }

  &:hover ${PanelTitle} {
    color: ${p => p.theme.colors.text};
  }

  &:focus-visible {
    outline: 2px solid ${p => p.theme.colors.main};
    outline-offset: 2px;
  }
`;

const PanelContent = styled.div`
  overflow-y: auto;
  overscroll-behavior-y: contain;
`;

const StyledCollapse = styled(Collapse)<{
  $embedded: boolean;
  $instant: boolean;
}>`
  /* Following a drag: the pointer sets the height, not the animation. */
  ${p => (p.$instant ? 'transition: none;' : '')}
  box-sizing: border-box;
  width: 100%;
  min-width: 0;
  padding-inline: 0;
  padding-bottom: ${p => (p.$embedded ? '0.35rem' : '0')};
`;

const Wrapper = styled.div<{ $embedded: boolean }>`
  display: flex;
  flex-direction: column;
  align-items: stretch;
  width: 100%;
  max-width: 100%;
  min-width: 0;
  max-height: fit-content;
  box-sizing: border-box;

  ${p =>
    p.$embedded
      ? `
    margin-top: 0.5rem;
    padding-top: 0.25rem;
  `
      : ''}
`;
