import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from 'react';
import { InputStyled, InputWrapper } from './forms/InputStyles';
import { IconButton } from './IconButton/IconButton';
import { FaChevronDown } from 'react-icons/fa6';
import { useCombobox } from 'downshift';
import { Column, Row } from './Row';
import styled, { css } from 'styled-components';
import { QuickScore } from 'quick-score';

/** What the menu widens to when the trigger is narrower and there is room. */
const PREFERRED_MENU_WIDTH = 400;
/** Breathing room kept between the menu and the edge of the window. */
const MENU_VIEWPORT_MARGIN = 8;

const supportsAnchorPositioning =
  'anchorName' in document.documentElement.style;

export type ComboBoxOption = {
  label: string;
  searchLabel: string;
  description?: string;
  /** Rendered before the label on the same row, muted — for a short code
   * that identifies the option (a country's `NL`, say). */
  prefix?: string;
  value: string;
};

type ComboBoxProps = {
  options: ComboBoxOption[];
  selectedItem: string | undefined;
  onSelect: (value: string | undefined) => void;
  subtle?: boolean;
};

export const ComboBox: React.FC<ComboBoxProps> = ({
  options,
  selectedItem,
  onSelect,
  subtle = false,
}) => {
  // Use Combobox does not work with the compiler.
  'use no memo';
  const id = useId();
  const anchorName = `--combo-box-${id.trim().replaceAll(':', '-')}`;
  const menuRef = useRef<HTMLUListElement>(null);
  const inputWrapperRef = useRef<HTMLDivElement>(null);
  const [menuAboveInput, setMenuAboveInput] = useState(false);
  const [menuWidth, setMenuWidth] = useState<number>();
  const [isFocused, setIsFocused] = useState(false);

  const [items, setItems] = useState(options);

  const quickScore = useMemo(() => {
    return new QuickScore(options, ['label']);
  }, [options]);

  const selectedOption = useMemo(
    () => options.find(option => option.value === selectedItem) ?? null,
    [options, selectedItem],
  );

  const {
    isOpen,
    getInputProps,
    getToggleButtonProps,
    getMenuProps,
    getItemProps,
    highlightedIndex,
    setHighlightedIndex,
    selectedItem: downshiftSelectedItem,
    setInputValue,
    openMenu,
  } = useCombobox({
    items,
    selectedItem: selectedOption,
    onInputValueChange: ({ inputValue }) => {
      setHighlightedIndex(0);

      if (inputValue === '') {
        setItems(options);

        return;
      }

      setItems(quickScore.search(inputValue).map(r => r.item));
    },
    itemToString: item => item?.label ?? '',
    onSelectedItemChange: ({ selectedItem: item }) => {
      if (item?.value !== selectedItem) {
        onSelect(item?.value);
      }
    },
  });

  useEffect(() => {
    setItems(options);
  }, [options]);

  const { ref: downShiftMenuRef, ...menuRest } = getMenuProps();

  const setMenuRef = useCallback((node: HTMLUListElement) => {
    // @ts-expect-error - downshift types are not correct, it's a callback ref, not a ref object
    downShiftMenuRef(node);
    menuRef.current = node;
  }, []);

  const checkMenuPosition = useCallback(() => {
    if (!inputWrapperRef.current) return;
    const inputWrapperPosition =
      inputWrapperRef.current.getBoundingClientRect();
    const isNearBottom = inputWrapperPosition.bottom > window.innerHeight - 320;
    setMenuAboveInput(isNearBottom);

    // The menu is a popover, so it lives in the top layer and percentage
    // widths resolve against the viewport, not the input it hangs off —
    // which is why this is measured here instead of being `min-width: 100%`.
    // A narrow trigger widens to PREFERRED_MENU_WIDTH so options aren't
    // cramped, but only where the whole of it fits beside the window edge:
    // otherwise the menu takes the trigger's own width and lines up with it,
    // rather than sticking out by whatever room happens to be left.
    const roomToTheRight =
      window.innerWidth - inputWrapperPosition.left - MENU_VIEWPORT_MARGIN;
    setMenuWidth(
      roomToTheRight >= PREFERRED_MENU_WIDTH
        ? Math.max(inputWrapperPosition.width, PREFERRED_MENU_WIDTH)
        : inputWrapperPosition.width,
    );
  }, []);

  useEffect(() => {
    if (!menuRef || !menuRef.current) return;

    if (isOpen) {
      menuRef.current.showPopover();
    } else {
      menuRef.current.hidePopover();
    }

    if (supportsAnchorPositioning)
      requestAnimationFrame(() => {
        checkMenuPosition();
      });
    else checkMenuPosition();
  }, [isOpen]);

  useEffect(() => {
    requestAnimationFrame(() => {
      checkMenuPosition();
    });
  }, [items]);

  useEffect(() => {
    if (!menuRef.current || !inputWrapperRef.current) return;

    if (!supportsAnchorPositioning) {
      import('@oddbird/css-anchor-positioning/fn').then(module => {
        module.default();
      });
    }
  }, [menuRef, inputWrapperRef]);

  const isActive = isFocused || isOpen;
  const showSubtle = subtle && !isActive;

  return (
    <Wrapper>
      <StyledInputWrapper
        anchorName={anchorName}
        ref={inputWrapperRef}
        className={menuAboveInput ? 'menu-above-input' : ''}
        $subtle={showSubtle}
      >
        <InputStyled
          {...getInputProps({
            onFocus: () => {
              setIsFocused(true);

              if (subtle) {
                setTimeout(() => {
                  setInputValue('');
                  openMenu();
                }, 0);
              }
            },
            onBlur: () => {
              setIsFocused(false);

              if (subtle) {
                setInputValue(downshiftSelectedItem?.label ?? '');
              }
            },
            onClick: e => {
              if (subtle) {
                // @ts-expect-error - Downshift custom event property
                e.preventDownshiftDefault = true;
              }
            },
            onMouseDown: e => {
              if (subtle) {
                // @ts-expect-error - Downshift custom event property
                e.preventDownshiftDefault = true;
              }
            },
          })}
        />
        {!showSubtle && (
          <IconButton {...getToggleButtonProps()}>
            <FaChevronDown />
          </IconButton>
        )}
      </StyledInputWrapper>
      <List
        $open={isOpen}
        $width={menuWidth}
        anchorName={anchorName}
        {...menuRest}
        ref={setMenuRef}
        popover='manual'
        className={menuAboveInput ? 'menu-above-input' : ''}
      >
        {isOpen && (
          <>
            {items.map((item, index) => (
              <ListItem
                key={item.value}
                data-selected={index === highlightedIndex}
                {...getItemProps({ item, index })}
              >
                <Row gap='0.5rem' center>
                  {item.prefix && <Prefix>{item.prefix}</Prefix>}
                  <Column gap='0.2rem'>
                    <span>{item.label}</span>
                    {item.description && (
                      <Description>{item.description}</Description>
                    )}
                  </Column>
                </Row>
              </ListItem>
            ))}
            {items.length === 0 && (
              <ListItem>
                <Description>No results</Description>
              </ListItem>
            )}
          </>
        )}
      </List>
    </Wrapper>
  );
};

const Wrapper = styled.div`
  position: relative;

  &:has(li) {
    ${InputWrapper} {
      box-shadow: ${p => p.theme.boxShadowSoft};
      border-radius: ${p => p.theme.radius} ${p => p.theme.radius} 0 0;
      border-bottom: none;

      &.menu-above-input {
        border-radius: 0 0 ${p => p.theme.radius} ${p => p.theme.radius};
        border-bottom: solid 1px ${p => p.theme.colors.main};
        border-top: none;
      }
    }
  }
`;

const ListItem = styled.li`
  list-style: none;
  margin: 0;
  padding: ${p => p.theme.size(1)} ${p => p.theme.size(2)};
  font-size: 0.9rem;
  &[data-selected='true'] {
    background-color: ${p => p.theme.colors.mainSelectedBg};
    color: ${p => p.theme.colors.mainSelectedFg};
  }
`;

const Description = styled.span`
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
`;

const Prefix = styled.span`
  color: ${p => p.theme.colors.textLight};
  /* Codes are short but proportionally spaced, so without a floor the labels
     after them come out ragged. */
  min-width: 3ch;
`;

const List = styled.ul<{
  $open: boolean;
  $width?: number;
  anchorName: string;
}>`
  max-height: ${p => p.theme.size(15)};
  overflow: auto;
  margin: 0;
  box-shadow: ${p => p.theme.boxShadowSoft};
  border-radius: 0 0 ${p => p.theme.radius} ${p => p.theme.radius};

  position-anchor: ${p => p.anchorName};
  top: anchor(bottom);
  left: anchor(left);
  bottom: unset;
  width: ${p => (p.$width ? `${p.$width}px` : 'max-content')};
  max-width: 95vw;
  background-color: ${p => p.theme.colors.bg};
  scrollbar-color: ${p => p.theme.colors.bg2} transparent;
  border: solid 1px ${p => p.theme.colors.main};
  border-top: none;
  position-try: flip-block;

  &.menu-above-input {
    top: unset;
    bottom: anchor(top);
    border-radius: ${p => p.theme.radius} ${p => p.theme.radius} 0 0;
    border-bottom: none;
    border-top: solid 1px ${p => p.theme.colors.main};
    box-shadow: none;
  }
`;

const StyledInputWrapper = styled(InputWrapper)<{
  anchorName: string;
  $subtle?: boolean;
}>`
  anchor-name: ${p => p.anchorName};

  ${p =>
    p.$subtle &&
    css`
      border-color: transparent;
      background-color: transparent;

      input {
        background-color: transparent;
        border-color: transparent;
        color: inherit;
        cursor: pointer;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      &:hover:has(input:not(:disabled)),
      &:hover {
        background-color: ${p.theme.colors.bg1};
        border-color: transparent;
      }
    `}
`;
