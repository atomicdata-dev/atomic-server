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
import { readableColor } from 'polished';
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
import { useBackToClose } from '../../hooks/useBackToClose';
import { isTouchPrimary } from '../../helpers/pointer';

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
   * label/keywords while keeping arrow+enter keyboard navigation. On by default.
   */
  searchable?: boolean;
  /**
   * Placeholder and accessible name of the filter input. Defaults to "Filter
   * actions"; name what the menu lists when it isn't actions (columns, say),
   * so the input doesn't read as a general search box.
   */
  searchPlaceholder?: string;
  searchLabel?: string;
  /** Shown when the filter query matches nothing. */
  noMatchText?: string;
  /**
   * An item to offer when the filter query matches nothing — for example
   * "Search the drive for …" when someone typed a page name into a menu that
   * can't find pages. Selectable with Enter like any other item.
   */
  noMatchItem?: (query: string) => MenuItemMinimial;
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
      remainingAttempts: number,
    ) => {
      // Every item is a divider or disabled — there is no valid index to
      // land on, so stop recursing instead of looping forever.
      if (remainingAttempts <= 0) {
        return 0;
      }

      const newIndex = loopingIndex(
        scopedStartingPoint + scopedOffset,
        items.length,
      );

      const additionalIncrement = getAdditionalOffest(offset);

      if (shouldSkip(items[newIndex])) {
        return findNextAvailable(
          newIndex,
          additionalIncrement,
          remainingAttempts - 1,
        );
      }

      return newIndex;
    };

    return findNextAvailable(startingPoint, offset, items.length);
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
export const matchesQuery = (item: MenuItemMinimial, query: string): boolean =>
  item.label.toLowerCase().includes(query) ||
  (item.keywords ?? []).some(keyword => keyword.toLowerCase().includes(query));

/**
 * How well an item matches a filter query, lower is better: a label starting
 * with the query beats one with a word starting with it, which beats a keyword
 * hit, which beats the query appearing mid-word. Typing "re" should put
 * "Reload" and "Restart" above "Add icon" (a keyword match).
 */
const matchRank = (item: MenuItemMinimial, query: string): number => {
  const label = item.label.toLowerCase();

  if (label.startsWith(query)) return 0;

  if (label.split(/\s+/).some(word => word.startsWith(query))) return 1;

  if ((item.keywords ?? []).some(k => k.toLowerCase().startsWith(query))) {
    return 2;
  }

  return label.includes(query) ? 3 : 4;
};

export function DropdownMenu({
  items,
  Trigger,
  isMainMenu,
  searchable = true,
  searchPlaceholder,
  searchLabel,
  noMatchText,
  noMatchItem,
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

  // Back closes the menu.
  useBackToClose(isActive, handleClose);

  useClickAwayListener([triggerRef, dropdownRef], handleClose, isActive, [
    'click',
  ]);

  const [query, setQuery] = useState('');
  const search = query.trim().toLowerCase();

  const filteredItems = useMemo(() => {
    if (!searchable || !search) {
      // Search-only items surface exclusively through the filter query.
      // Dropping them can strand a divider at the end or double one up.
      return items
        .filter(item => !isItem(item) || !item.searchOnly)
        .filter(
          (item, i, all) =>
            isItem(item) ||
            (i > 0 && i < all.length - 1 && all[i - 1] !== DIVIDER),
        );
    }

    // Dividers are dropped while filtering.
    return items
      .filter(item => isItem(item) && matchesQuery(item, search))
      .map((item, i) => ({ item, i }))
      .sort(
        (a, b) =>
          matchRank(a.item as MenuItemMinimial, search) -
            matchRank(b.item as MenuItemMinimial, search) || a.i - b.i,
      )
      .map(({ item }) => item);
  }, [items, searchable, search]);

  // A matching section header alone isn't a match: nothing to pick under it.
  const noMatch =
    searchable &&
    !!search &&
    !filteredItems.some(item => isItem(item) && !item.disabled && !item.header);

  const normalizedItems = useMemo(
    () =>
      noMatch && noMatchItem
        ? [noMatchItem(query.trim())]
        : normalizeItems(filteredItems),
    [filteredItems, noMatch, noMatchItem, query],
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

  const positionMenu = useCallback(() => {
    const menu = dropdownRef.current;
    const trigger = triggerRef.current;

    if (!menu || !trigger) return;

    const dialog = menu.closest('dialog');
    const viewport = window.visualViewport;
    const visibleTop = viewport?.scale === 1 ? viewport.offsetTop : 0;
    const visibleHeight =
      viewport?.scale === 1 ? viewport.height : window.innerHeight;
    const visibleBottom = visibleTop + visibleHeight;

    // Keyboard animation resizes the visual viewport without necessarily
    // changing CSS viewport units. Keep the menu scrollable inside that area.
    if (!dialog) {
      menu.style.maxHeight = `${Math.max(0, Math.min(window.innerHeight * 0.8, visibleHeight - 16))}px`;
    }

    // Layout size, not getBoundingClientRect: the open transition scales the
    // menu (`scale: 0.95`), and a rect measured mid-transition is 5% too
    // small. The menu would then end up that much too low once it settled,
    // and nothing re-positions it (a ResizeObserver ignores transforms).
    const menuRect = { width: menu.offsetWidth, height: menu.offsetHeight };

    if (anchorPoint) {
      const left =
        anchorPoint.x + menuRect.width > window.innerWidth
          ? anchorPoint.x - menuRect.width
          : anchorPoint.x;
      const preferredTop =
        anchorPoint.y + menuRect.height > visibleBottom
          ? anchorPoint.y - menuRect.height
          : anchorPoint.y;

      menu.style.left = `${Math.max(0, left)}px`;
      menu.style.top = `${Math.max(visibleTop + 8, Math.min(preferredTop, visibleBottom - menuRect.height - 8))}px`;

      return;
    }

    const triggerRect = trigger.getBoundingClientRect();

    if (dialog) {
      const dialogRect = dialog.getBoundingClientRect();
      const relativeTop = triggerRect.y - dialogRect.y;
      const relativeLeft = triggerRect.x - dialogRect.x;
      const topPos = relativeTop - menuRect.height;

      menu.style.top = `${topPos < 0 ? relativeTop + triggerRect.height : topPos}px`;

      const leftPos = relativeLeft - menuRect.width;
      menu.style.left = `${leftPos < 0 ? relativeLeft : relativeLeft - menuRect.width + triggerRect.width}px`;

      return;
    }

    // Prefer above the trigger; clamp to the visible viewport if the keyboard
    // has covered the trigger or reduced the available space.
    const above = triggerRect.y - menuRect.height - MENU_TRIGGER_GAP;
    const preferredTop =
      above < visibleTop ? triggerRect.bottom + MENU_TRIGGER_GAP : above;
    menu.style.top = `${Math.max(visibleTop + 8, Math.min(preferredTop, visibleBottom - menuRect.height - 8))}px`;

    const leftPos = triggerRect.x - menuRect.width;
    menu.style.left = `${leftPos < 0 ? triggerRect.x : triggerRect.x - menuRect.width + triggerRect.width}px`;
  }, [anchorPoint]);

  useEffect(() => {
    if (!isActive) return;

    let frame = 0;

    const schedulePosition = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(positionMenu);
    };

    const viewport = window.visualViewport;
    // Absent in jsdom and very old browsers; the viewport and scroll
    // listeners below still keep the menu in place there.
    const observer =
      typeof ResizeObserver === 'undefined'
        ? undefined
        : new ResizeObserver(schedulePosition);

    if (dropdownRef.current) observer?.observe(dropdownRef.current);
    viewport?.addEventListener('resize', schedulePosition);
    viewport?.addEventListener('scroll', schedulePosition);
    window.addEventListener('resize', schedulePosition);
    window.addEventListener('scroll', schedulePosition, true);

    return () => {
      cancelAnimationFrame(frame);
      observer?.disconnect();
      viewport?.removeEventListener('resize', schedulePosition);
      viewport?.removeEventListener('scroll', schedulePosition);
      window.removeEventListener('resize', schedulePosition);
      window.removeEventListener('scroll', schedulePosition, true);
    };
  }, [isActive, positionMenu]);

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

      positionMenu();

      // Typing in the filter changes which items show. Keep the width the menu
      // was positioned with, so a longer item (the no-match fallback, say)
      // wraps instead of pushing the menu past the viewport edge.
      if (searchable) {
        dropdownRef.current.style.width = `${dropdownRef.current.getBoundingClientRect().width}px`;
      }

      // The menu is positioned while visibility:hidden, so the entrance
      // transition must start AFTER it becomes visible — one frame later —
      // or it plays unseen and the menu appears to pop in.
      const reveal = () => {
        const menu = dropdownRef.current!;
        menu.style.visibility = 'visible';

        // Focus only after this exact menu has been revealed. A separate
        // effect's RAF can run before the positioning RAF under React's
        // scheduling, and browsers refuse focus on visibility:hidden inputs.
        // Not on a touch device: focusing a text field there raises the
        // on-screen keyboard over the menu the moment it opens.
        if (searchable && !isTouchPrimary()) {
          searchInputRef.current?.focus();
        } else if (!menu.contains(document.activeElement)) {
          menu.focus();
        }

        requestAnimationFrame(() => {
          dropdownRef.current?.setAttribute('data-positioned', 'true');
        });
      };

      reveal();
    });
  }, [isActive, handleClose, setIsActive, positionMenu, searchable]);

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
    // Also while typing: Cmd/Ctrl+M means nothing to a text field, and left to
    // the browser it minimized the window on a Mac mid-sentence in a document.
    {
      enabled: !!isMainMenu,
      enableOnContentEditable: true,
      enableOnFormTags: ['INPUT', 'TEXTAREA', 'SELECT'],
    },
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
                  placeholder={searchPlaceholder ?? 'Filter actions…'}
                  aria-label={searchLabel ?? 'Filter actions'}
                  value={query}
                  onChange={e => {
                    setQuery(e.target.value);
                    setUseKeys(true);
                    setSelectedIndex(0);
                  }}
                />
              </SearchInputWrapper>
            )}
            {noMatch && (
              <NoResults>{noMatchText ?? 'No matching actions'}</NoResults>
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
  --menu-highlight-bg: ${p =>
    p.theme.colorful ? p.theme.colors.main : p.theme.colors.mainSelectedBg};
  --menu-highlight-fg: ${p =>
    p.theme.colorful
      ? readableColor(p.theme.colors.main)
      : p.theme.colors.mainSelectedFg};
  /* Transparent so the menu's frosted surface shows through. */
  --menu-item-bg: ${p =>
    p.selected ? 'var(--menu-highlight-bg)' : 'transparent'};
  --menu-item-fg: ${p =>
    p.selected ? 'var(--menu-highlight-fg)' : p.theme.colors.text};
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

  &:hover:not(:disabled),
  &:focus-visible:not(:disabled) {
    --menu-item-bg: var(--menu-highlight-bg);
    --menu-item-fg: var(--menu-highlight-fg);

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

/* Pinned while the list under it scrolls. */
const SearchInputWrapper = styled.div`
  position: sticky;
  top: 0;
  z-index: 1;
  padding: 0.4rem 0.5rem;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  margin-bottom: 0.4rem;
  /* Opaque: the menu's own surface is translucent, and the rows scrolling
     under the filter must not show through it. */
  background: ${p => p.theme.colors.bgBody};
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
  /* A searchable menu lists everything (the resource's actions and the app's
     places), so it scrolls within a height that leaves the page visible. */
  max-height: ${p => (p.searchable ? 'min(60vh, 32rem)' : '80vh')};
  ${floatingSurface}
  /* A searchable menu's pinned filter supplies the top spacing itself, so
     rows scrolling up disappear under it instead of into a gap above it. */
  padding-top: ${p => (p.searchable ? '0' : '0.4rem')};
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
