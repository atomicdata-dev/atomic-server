import {
  useContext,
  useId,
  useMemo,
  useRef,
  useState,
  useCallback,
  PropsWithChildren,
  ReactNode,
  useEffect,
  type JSX,
} from 'react';
import { useHotkeys } from 'react-hotkeys-hook';
import { styled } from 'styled-components';
import { useClickAwayListener } from '../../hooks/useClickAwayListener';
import { Button } from '../Button';
import { DropdownTriggerComponent as DropdownTriggerComponent } from './DropdownTrigger';
import { shortcuts } from '../HotKeyWrapper';
import { Shortcut } from '../Shortcut';
import { transition } from '../../helpers/transition';
import { createPortal } from 'react-dom';
import { DropdownPortalContext } from './dropdownContext';
import { loopingIndex } from '../../helpers/loopingIndex';
import { useControlLock } from '../../hooks/useControlLock';
import { useDialogTreeInfo } from '../Dialog/dialogContext';
import { floatingSurface } from '../floatingSurface';

export const DIVIDER = 'divider' as const;

/** Space between a menu and its trigger, so the trigger stays clickable. */
const MENU_TRIGGER_GAP = 4;

export type MenuItemMinimial = {
  onClick: () => unknown;
  label: string;
  helper?: string;
  id: string;
  icon?: ReactNode;
  /** Compact trailing metadata, such as a drive service state. */
  suffix?: ReactNode;
  disabled?: boolean;
  header?: boolean;
  /**
   * Leaves the menu open after activating this item, for menus whose items
   * toggle state (show/hide columns, say) rather than navigate away — otherwise
   * every toggle costs a reopen.
   */
  keepOpen?: boolean;
  /** Keyboard shortcut helper */
  shortcut?: string;
  /** Extra search terms for searchable menus. */
  keywords?: string[];
  /**
   * Hidden from the default listing; only appears in searchable menus while
   * the filter query matches its label/keywords.
   */
  searchOnly?: boolean;
};

export type DropdownItem = typeof DIVIDER | MenuItemMinimial;

interface DropdownMenuProps {
  /** The list of menu items */
  items: DropdownItem[];
  Trigger: DropdownTriggerComponent;
  /** Enables the keyboard shortcut */
  isMainMenu?: boolean;
  /**
   * Renders a filter input at the top of the menu that narrows the items by
   * label/keywords while keeping arrow+enter keyboard navigation.
   */
  searchable?: boolean;
  bindActive?: (active: boolean) => void;
  /**
   * When set, positions the menu at this viewport point (a right-click / context
   * menu) instead of anchoring it to the trigger element. Pair with
   * `AutoOpenTrigger` to open it programmatically at the cursor.
   */
  anchorPoint?: { x: number; y: number };
}

export const isItem = (
  item: MenuItemMinimial | string | undefined,
): item is MenuItemMinimial =>
  typeof item !== 'string' && typeof item?.label === 'string';

const shouldSkip = (item?: DropdownItem) => !isItem(item) || item.disabled;

const getAdditionalOffest = (increment: number) =>
  increment === 0 ? 1 : Math.sign(increment);

/**
 * Returns a function that finds the next available index, it skips disabled
 * items and dividers and loops around when at the start or end of the list.
 * Returns 0 when no suitable index is found.
 */
const createIndexOffset =
  (items: DropdownItem[]) => (startingPoint: number, offset: number) => {
    const findNextAvailable = (
      scopedStartingPoint: number,
      scopedOffset: number,
    ) => {
      const newIndex = loopingIndex(
        scopedStartingPoint + scopedOffset,
        items.length,
      );

      const additionalIncrement = getAdditionalOffest(offset);

      if (shouldSkip(items[newIndex])) {
        return findNextAvailable(newIndex, additionalIncrement);
      }

      return newIndex;
    };

    return findNextAvailable(startingPoint, offset);
  };

function normalizeItems(items: DropdownItem[]) {
  return items.reduce((acc: DropdownItem[], current, i) => {
    // If the item is a divider at the start or end of the list, remove it.
    if ((i === 0 || i === items.length - 1) && !isItem(current)) {
      return acc;
    }

    // If the current and previous item are dividers, remove the current one.
    if (!isItem(current) && !isItem(acc[i - 1])) {
      return acc;
    }

    return [...acc, current];
  }, []);
}

/**
 * Menu that opens on click and shows a bunch of items. Closes on Escape and on
 * clicking outside. Use arrow keys to select items, and open items on Enter.
 * Renders the Dropdown on a place where there is room on screen.
 */
const matchesQuery = (item: MenuItemMinimial, query: string): boolean =>
  item.label.toLowerCase().includes(query) ||
  (item.keywords ?? []).some(keyword => keyword.toLowerCase().includes(query));

export function DropdownMenu({
  items,
  Trigger,
  isMainMenu,
  searchable,
  bindActive = () => undefined,
  anchorPoint,
}: DropdownMenuProps): JSX.Element {
  const menuId = useId();
  const triggerId = useId();
  const dropdownRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const [isActive, _setIsActive] = useState(false);
  const { inDialog } = useDialogTreeInfo();

  useControlLock(isActive);

  const setIsActive = useCallback(
    (active: boolean) => {
      _setIsActive(active);
      bindActive(active);
    },
    [bindActive],
  );

  const handleClose = useCallback(() => {
    triggerRef.current?.focus();
    setIsActive(false);
  }, [setIsActive]);

  useClickAwayListener([triggerRef, dropdownRef], handleClose, isActive, [
    'click',
  ]);

  const [query, setQuery] = useState('');
  const search = query.trim().toLowerCase();

  const filteredItems = useMemo(() => {
    if (!searchable || !search) {
      // Search-only items surface exclusively through the filter query.
      return items.filter(item => !isItem(item) || !item.searchOnly);
    }

    // Dividers are dropped while filtering.
    return items.filter(item => isItem(item) && matchesQuery(item, search));
  }, [items, searchable, search]);

  const normalizedItems = useMemo(
    () => normalizeItems(filteredItems),
    [filteredItems],
  );
  const hasSelectable = normalizedItems.some(item => !shouldSkip(item));

  const getNewIndex = createIndexOffset(normalizedItems);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  // Filtering can leave the stored index on a divider/disabled/out-of-range
  // slot; resolve to the nearest selectable item for highlight and Enter.
  const effectiveSelectedIndex =
    hasSelectable && shouldSkip(normalizedItems[selectedIndex])
      ? getNewIndex(0, 0)
      : selectedIndex;
  // if the keyboard is used to navigate the menu items
  const [useKeys, setUseKeys] = useState(true);

  const handleToggle = useCallback(() => {
    if (isActive) {
      handleClose();

      return;
    }

    setQuery('');
    setIsActive(true);

    requestAnimationFrame(() => {
      if (!triggerRef.current || !dropdownRef.current) {
        return;
      }

      const menuRect = dropdownRef.current.getBoundingClientRect();

      // The menu is positioned while visibility:hidden, so the entrance
      // transition must start AFTER it becomes visible — one frame later —
      // or it plays unseen and the menu appears to pop in.
      const reveal = () => {
        dropdownRef.current!.style.visibility = 'visible';
        requestAnimationFrame(() => {
          dropdownRef.current?.setAttribute('data-positioned', 'true');
        });
      };

      // A right-click / context menu: position at the cursor point with the
      // usual convention (below-right, flipping left/up when it would overflow
      // the viewport, clamped to stay on-screen).
      if (anchorPoint) {
        const left =
          anchorPoint.x + menuRect.width > window.innerWidth
            ? anchorPoint.x - menuRect.width
            : anchorPoint.x;
        const top =
          anchorPoint.y + menuRect.height > window.innerHeight
            ? anchorPoint.y - menuRect.height
            : anchorPoint.y;

        dropdownRef.current.style.left = `${Math.max(0, left)}px`;
        dropdownRef.current.style.top = `${Math.max(0, top)}px`;
        reveal();

        return;
      }

      const triggerRect = triggerRef.current.getBoundingClientRect();

      // Check if we're inside a dialog
      const dialog = dropdownRef.current.closest('dialog');

      // TODO: Use CSS anchor positioning instead.
      if (dialog) {
        // For dialogs, use absolute positioning relative to the dialog
        const dialogRect = dialog.getBoundingClientRect();
        const relativeTop = triggerRect.y - dialogRect.y;
        const relativeLeft = triggerRect.x - dialogRect.x;

        const topPos = relativeTop - menuRect.height;

        // If the top is outside of the dialog, render it below
        if (topPos < 0) {
          dropdownRef.current.style.top = `${relativeTop + triggerRect.height}px`;
        } else {
          dropdownRef.current.style.top = `${topPos}px`;
        }

        const leftPos = relativeLeft - menuRect.width;

        // If the left is outside of the dialog, render it to the right
        if (leftPos < 0) {
          dropdownRef.current.style.left = `${relativeLeft}px`;
        } else {
          dropdownRef.current.style.left = `${relativeLeft - menuRect.width + triggerRect.width}px`;
        }
      } else {
        // Prefer opening above the trigger, below when there's no room. A
        // small gap instead of overlapping the trigger — covering it half-way
        // made it unclickable for toggling the menu closed.
        const topPos = triggerRect.y - menuRect.height - MENU_TRIGGER_GAP;

        if (topPos < 0) {
          dropdownRef.current.style.top = `${triggerRect.bottom + MENU_TRIGGER_GAP}px`;
        } else {
          dropdownRef.current.style.top = `${topPos}px`;
        }

        const leftPos = triggerRect.x - menuRect.width;

        // If the left is outside of the screen, render it to the right
        if (leftPos < 0) {
          dropdownRef.current.style.left = `${triggerRect.x}px`;
        } else {
          dropdownRef.current.style.left = `${triggerRect.x - menuRect.width + triggerRect.width}px`;
        }
      }

      reveal();
    });
  }, [isActive, setIsActive, anchorPoint]);

  const handleMouseOverMenu = useCallback(() => {
    setUseKeys(false);
  }, []);

  const handleTriggerActivate = useCallback(() => {
    setUseKeys(true);
    setSelectedIndex(hasSelectable ? getNewIndex(0, 0) : 0);
    handleToggle();
  }, [handleToggle, hasSelectable]);

  // Close the menu
  useHotkeys('esc', handleClose, { enabled: isActive });
  useHotkeys(
    'tab',
    e => {
      e.preventDefault();
      handleClose();
    },
    { enabled: isActive },
  );

  // Toggle menu
  useHotkeys(
    shortcuts.menu,
    e => {
      e.preventDefault();
      handleToggle();
      setUseKeys(true);
    },
    { enabled: !!isMainMenu },
    [isActive],
  );

  // Arrow navigation + Enter/Escape are handled on the menu element itself
  // (not via the global `useHotkeys` above): the menu renders in a portal, and
  // react-hotkeys-hook's document listener does NOT fire for keys dispatched
  // while focus is inside that portal — so after the first keypress moved focus
  // into the menu, arrows stopped working. Handling `onKeyDown` on the menu (to
  // which keydowns from the focused item bubble) is reliable.
  const handleMenuKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setUseKeys(true);

      if (hasSelectable) {
        setSelectedIndex(getNewIndex(effectiveSelectedIndex, 1));
      }
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setUseKeys(true);

      if (hasSelectable) {
        setSelectedIndex(getNewIndex(effectiveSelectedIndex, -1));
      }
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const item = normalizedItems[effectiveSelectedIndex];

      if (isItem(item) && !item.disabled) {
        item.onClick();

        if (item.keepOpen) {
          return;
        }
      }

      handleClose();
    } else if (e.key === 'Escape' || e.key === 'Tab') {
      e.preventDefault();
      handleClose();
    }
  };

  // Focus the menu on open so keyboard navigation works even when it opened at
  // the cursor with no highlighted item (context menus). Only when focus isn't
  // already inside it — a normal dropdown highlights + focuses its first item.
  // Deferred to the frame AFTER the positioning RAF made the menu visible —
  // focusing a visibility:hidden element is refused (which is also why the
  // search input can't use the autoFocus attribute).
  useEffect(() => {
    if (!isActive) {
      return;
    }

    const raf = requestAnimationFrame(() => {
      if (searchable) {
        searchInputRef.current?.focus();

        return;
      }

      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(document.activeElement)
      ) {
        dropdownRef.current.focus();
      }
    });

    return () => cancelAnimationFrame(raf);
  }, [isActive, searchable]);

  // A pointerdown on the trigger while the menu is open must NOT close the
  // menu via the blur handler below — the same click's toggle would then
  // REopen it, making the trigger appear unable to close the menu.
  const pointerDownOnTrigger = useRef(false);

  useEffect(() => {
    if (!isActive) {
      pointerDownOnTrigger.current = false;

      return;
    }

    const onPointerDown = (e: PointerEvent) => {
      pointerDownOnTrigger.current = !!triggerRef.current?.contains(
        e.target as Node,
      );
    };

    document.addEventListener('pointerdown', onPointerDown, true);

    return () =>
      document.removeEventListener('pointerdown', onPointerDown, true);
  }, [isActive]);

  const handleBlur = useCallback(() => {
    // Doesn't work without delay, maybe the browser sets document.activeElement after firering the blur event?
    requestAnimationFrame(() => {
      if (!dropdownRef.current) return;

      if (
        pointerDownOnTrigger.current ||
        document.activeElement === triggerRef.current
      ) {
        return;
      }

      if (!dropdownRef.current.contains(document.activeElement)) {
        handleClose();
      }
    });
  }, [handleClose]);

  return (
    <>
      <Trigger
        id={triggerId}
        ref={triggerRef}
        onClick={handleTriggerActivate}
        isActive={isActive}
        menuId={menuId}
      />
      {isActive && (
        <DropdownPortal>
          <Menu
            ref={dropdownRef}
            position={inDialog ? 'absolute' : 'fixed'}
            id={menuId}
            tabIndex={-1}
            onKeyDown={handleMenuKeyDown}
            onMouseOver={handleMouseOverMenu}
            onBlur={handleBlur}
            aria-labelledby={triggerId}
            role='menu'
            searchable={searchable}
          >
            {searchable && (
              <SearchInputWrapper>
                <SearchInput
                  ref={searchInputRef}
                  type='text'
                  placeholder='Filter actions…'
                  aria-label='Filter actions'
                  value={query}
                  onChange={e => {
                    setQuery(e.target.value);
                    setUseKeys(true);
                    setSelectedIndex(0);
                  }}
                />
              </SearchInputWrapper>
            )}
            {searchable && search && !hasSelectable && (
              <NoResults>No matching actions</NoResults>
            )}
            {normalizedItems.map((props, i) => {
              if (!isItem(props)) {
                return <ItemDivider key={i} />;
              }

              const {
                label,
                onClick,
                helper,
                id,
                disabled,
                shortcut,
                suffix,
                icon,
                header,
                keepOpen,
              } = props;

              return (
                <MenuItem
                  onClick={() => {
                    if (!keepOpen) {
                      handleClose();
                    }

                    onClick();
                  }}
                  id={id}
                  data-testid={`menu-item-${id}`}
                  disabled={disabled}
                  key={id}
                  helper={shortcut ? `${helper} (${shortcut})` : helper}
                  label={label}
                  selected={useKeys && effectiveSelectedIndex === i}
                  icon={icon}
                  shortcut={shortcut}
                  suffix={suffix}
                  header={header}
                  // In searchable mode focus stays in the filter input;
                  // selection is shown by highlight + scrolled into view.
                  focusOnSelect={!searchable}
                />
              );
            })}
          </Menu>
        </DropdownPortal>
      )}
    </>
  );
}

const DropdownPortal = ({ children }: PropsWithChildren) => {
  const portalRef = useContext(DropdownPortalContext);

  if (!portalRef.current) {
    return null;
  }

  return createPortal(children, portalRef.current);
};

export interface MenuItemSidebarProps extends MenuItemMinimial {
  handleClickItem?: () => unknown;
  header?: boolean;
}

interface MenuItemPropsExtended extends MenuItemSidebarProps {
  selected: boolean;
  /**
   * Whether the item grabs DOM focus when selected (default). Searchable
   * menus keep focus in their filter input and only scroll the item into
   * view.
   */
  focusOnSelect?: boolean;
}

export function MenuItem({
  onClick,
  selected,
  helper,
  disabled,
  shortcut,
  suffix,
  icon,
  label,
  header,
  focusOnSelect = true,
  keywords: _keywords,
  ...props
}: MenuItemPropsExtended): JSX.Element {
  const ref = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!selected) {
      return;
    }

    if (focusOnSelect) {
      if (document.activeElement !== ref.current) {
        ref.current?.focus();
      }
    } else {
      ref.current?.scrollIntoView({ block: 'nearest' });
    }
  }, [selected, focusOnSelect]);

  if (header) {
    return (
      <MenuItemHeader id={props.id}>
        {icon}
        <StyledLabel>{label}</StyledLabel>
      </MenuItemHeader>
    );
  }

  return (
    <MenuItemStyled
      clean
      ref={ref}
      onClick={onClick}
      selected={selected}
      // The keyboard selection is visible state, but in a searchable menu
      // focus stays in the filter input, so nothing else in the DOM says
      // which item Enter will run. Tests and assistive tooling read this.
      data-selected={selected ? 'true' : undefined}
      title={helper}
      disabled={disabled}
      role='menuitem'
      tabIndex={-1}
      {...props}
    >
      {icon}
      <StyledLabel>{label}</StyledLabel>
      {suffix}
      {shortcut && <StyledShortcut shortcut={shortcut} />}
    </MenuItemStyled>
  );
}

const StyledShortcut = styled(Shortcut)`
  margin-left: 0.3rem;
  color: ${p => p.theme.colors.textLight};
`;

const StyledLabel = styled.span`
  flex: 1;
`;

const MenuItemHeader = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.6rem 1rem 0.2rem 1rem;
  font-size: 0.75rem;
  text-transform: uppercase;
  font-weight: bold;
  letter-spacing: 0.05rem;
  color: ${p => p.theme.colors.main};
  opacity: 0.8;

  & svg {
    color: ${p => p.theme.colors.main};
  }
`;

interface MenuItemStyledProps {
  selected: boolean;
}

const MenuItemStyled = styled(Button)<MenuItemStyledProps>`
  /* Transparent so the menu's frosted surface shows through. */
  --menu-item-bg: ${p =>
    p.selected ? p.theme.colors.mainSelectedBg : 'transparent'};
  --menu-item-fg: ${p =>
    p.selected ? p.theme.colors.mainSelectedFg : p.theme.colors.text};
  align-items: center;
  display: flex;
  gap: 0.5rem;
  width: 100%;
  text-align: left;
  color: var(--menu-item-fg);
  padding: 0.4rem 1rem;
  height: auto;
  background-color: var(--menu-item-bg);
  outline: none;

  & svg {
    color: var(--menu-item-fg);
  }

  &:hover {
    --menu-item-bg: ${p => p.theme.colors.mainSelectedBg};
    --menu-item-fg: ${p => p.theme.colors.mainSelectedFg};

    @media (prefers-contrast: more) {
      --menu-item-bg: ${p => (p.theme.darkMode ? 'white' : 'black')};
      --menu-item-fg: ${p => (p.theme.darkMode ? 'black' : 'white')};
    }
  }
  &:active {
    filter: brightness(0.9);
  }
  &:disabled {
    color: ${p => p.theme.colors.textLight2};
    cursor: default;
    background-color: transparent;

    & svg {
      color: ${p => p.theme.colors.textLight2};
    }
  }
`;

const ItemDivider = styled.div`
  width: 100%;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
`;

const SearchInputWrapper = styled.div`
  padding: 0 0.5rem 0.4rem 0.5rem;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  margin-bottom: 0.4rem;
`;

const SearchInput = styled.input`
  width: 100%;
  border: none;
  outline: none;
  background: transparent;
  color: ${p => p.theme.colors.text};
  font-size: inherit;
  padding: 0.2rem 0.5rem;

  &::placeholder {
    color: ${p => p.theme.colors.textLight};
  }
`;

const NoResults = styled.div`
  padding: 0.4rem 1rem;
  color: ${p => p.theme.colors.textLight};
`;

const Menu = styled.div<{
  position?: 'fixed' | 'absolute';
  searchable?: boolean;
}>`
  visibility: hidden;
  font-size: 0.9rem;
  overflow: auto;
  max-height: 80vh;
  ${floatingSurface}
  padding-top: 0.4rem;
  padding-bottom: 0.4rem;
  /* Focused programmatically on open for keyboard nav; items show selection. */
  outline: none;
  position: ${p => p.position || 'fixed'};
  z-index: ${p => p.theme.zIndex.dropdown};
  width: auto;
  min-width: ${p => (p.searchable ? '15rem' : 'auto')};
  /* Entrance runs when data-positioned is set — one frame after the menu is
     positioned and made visible — so the transition is actually seen. */
  opacity: 0;
  scale: 0.95;
  ${transition('opacity', 'scale')};

  &[data-positioned='true'] {
    opacity: 1;
    scale: 1;
  }
`;
