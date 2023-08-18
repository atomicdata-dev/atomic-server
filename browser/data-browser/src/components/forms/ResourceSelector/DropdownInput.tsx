import React, {
  useEffect,
  useRef,
  useState,
  useCallback,
  useContext,
} from 'react';
import { useHotkeys } from 'react-hotkeys-hook';
import * as RadixPopover from '@radix-ui/react-popover';
import { useResource, useTitle } from '@tomic/react';
import { FaCaretDown, FaTimes, FaTrash } from 'react-icons/fa';
import { styled, css } from 'styled-components';
import { Hit, useLocalSearch } from '../../../helpers/useLocalSearch';
import { ButtonInput } from '../../Button';
import { InputOverlay, InputStyled, InputWrapper } from '../InputStyles';
import ResourceLine, {
  ResourceLineDescription,
} from '../../../views/ResourceLine';
import { useClickAwayListener } from '../../../hooks/useClickAwayListener';
import { useAvailableSpace } from '../hooks/useAvailableSpace';
import { DropdownPortalContext } from '../../Dropdown/dropdownContext';
import { ScrollArea } from '../../ScrollArea';
import { ErrorLook } from '../../ErrorLook';
import { InlineOverlay } from './InlineOverlay';

interface DropDownListProps {
  required?: boolean;
  initial?: string;
  /** Is called when a value is selected */
  onUpdate: (value: string | undefined) => void;
  /** A set of Subjects from which the user can choose */
  options: string[];
  /** Is called when the entire value is removed. Renders a trashcan button if passed */
  onRemove?: () => void;
  placeholder?: string;
  disabled?: boolean;
  /**
   * URL of the Class that is used to instantiate new items in the Dropdown.
   * Used in combination with `onCreateClick`
   */
  classType?: string;
  /** Called after pressing the plus icon */
  onCreateClick?: () => void;
  /** Called after change of input - also if no value has been selected yet */
  onInputChange?: (newInput: string) => void;
  onBlur?: () => void;
  invalid?: boolean;
}

type CreateOption = {
  type: 'createOption';
};

function isCreateOption(option: unknown): option is CreateOption {
  // @ts-ignore
  return option?.type === 'createOption';
}

/**
 * Renders an input field with a dropdown menu. You can search through the
 * items, select them from a list, clear the entire thing, add new items.
 *
 * If you want to allow adding new items, pass an onCreateClick prop.
 */
export const DropdownInput: React.FC<DropDownListProps> = ({
  required,
  initial,
  placeholder,
  onRemove,
  onUpdate,
  options,
  disabled,
  classType,
  onCreateClick,
  onInputChange,
  onBlur,
  invalid,
  ...props
}) => {
  const [inputValue, setInputValue] = useState<string>(initial ? initial : '');
  const [selectedItem, setSelectedItem] = useState<string | undefined>(initial);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const [isFocus, setIsFocus] = useState<boolean>(false);
  // if the keyboard is used to navigate the dropdown items
  // hides the mouse cursor interactions with elements
  const [useKeys, setUseKeys] = useState<boolean>(false);
  const dropdownRef = useRef(null);
  const openMenuButtonRef = useRef(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const containerRef = useContext(DropdownPortalContext);
  const {
    ref: inputWrapperRef,
    above,
    below,
    width,
  } = useAvailableSpace<HTMLDivElement>(isOpen);

  /** Close the menu and set the value */
  const handleClickOutside = useCallback(() => {
    setIsOpen(false);
    setIsFocus(false);
    onBlur?.();
    // Does this do what it should?
    setSelectedItem(inputValue);
  }, [onBlur, inputValue]);

  useClickAwayListener(
    [dropdownRef, openMenuButtonRef, inputRef],
    handleClickOutside,
    isOpen,
  );

  // Sometimes the initial value changes on render, and then we should update it accordingly
  useEffect(() => {
    setIsFocus(false);
    setSelectedItem(initial);
  }, [initial]);

  // Close the menu
  useHotkeys(
    'esc',
    e => {
      e.preventDefault();
      setIsOpen(false);
    },
    { enabled: isOpen, enableOnTags: ['INPUT'] },
  );

  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const val = e.target.value;
      setInputValue(val);
      onInputChange && onInputChange(val);
      setUseKeys(true);
      setIsFocus(true);
      setIsOpen(true);
      setSelectedIndex(-1);

      if (val === '') {
        setSelectedItem(undefined);
      } else {
        setSelectedItem(val);
      }
    },
    [onInputChange, setInputValue],
  );

  function clearSelection() {
    setInputValue('');
    setSelectedItem(undefined);
    onUpdate(undefined);
    inputRef.current?.focus();
  }

  function handleFocus(e: React.FocusEvent<HTMLInputElement>) {
    setSelectedIndex(-1);
    setIsFocus(true);
    setIsOpen(true);
    e.target.select();
    // This delay helps make sure the entire text is selected
    setTimeout(function () {
      e.target.select();
    }, 20);
  }

  const handleItemSelected = useCallback(
    (item: string) => {
      setInputValue(item);
      setSelectedItem(item);
      onUpdate(item);
      setIsOpen(false);
      setIsFocus(false);
    },
    [setInputValue, setSelectedItem, onUpdate, setIsOpen],
  );

  return (
    <RadixPopover.Root open={isOpen}>
      <DropDownStyled>
        <RadixPopover.Anchor>
          <InputWrapper ref={inputWrapperRef}>
            <ResourceInputOverlayWrapper>
              {selectedItem && !isFocus && (
                <StyledInputOverlay>
                  {invalid ? (
                    <ErrorLook>{selectedItem}</ErrorLook>
                  ) : (
                    <InlineOverlay subject={selectedItem} />
                  )}
                </StyledInputOverlay>
              )}
              <InputStyled
                onFocus={handleFocus}
                disabled={disabled}
                size={5}
                required={required}
                placeholder={placeholder}
                value={inputValue}
                onChange={handleInputChange}
                ref={inputRef}
                {...props}
              />
            </ResourceInputOverlayWrapper>
            {selectedItem ? (
              <ButtonInput
                disabled={disabled}
                type='button'
                onClick={clearSelection}
                title='clear selection'
                aria-label='clear selection'
              >
                <FaTimes />
              </ButtonInput>
            ) : null}
            {options.length > 0 && selectedItem === undefined && (
              <ButtonInput
                disabled={disabled}
                type='button'
                onClick={() => setIsOpen(!isOpen)}
                title='toggle menu'
                ref={openMenuButtonRef}
                aria-label={'toggle menu'}
              >
                <FaCaretDown />
              </ButtonInput>
            )}
            {onRemove !== undefined && (
              <ButtonInput
                disabled={disabled}
                type='button'
                onClick={onRemove}
                title='remove item'
                aria-label='remove item'
              >
                <FaTrash />
              </ButtonInput>
            )}
          </InputWrapper>
        </RadixPopover.Anchor>
        <RadixPopover.Portal container={containerRef.current}>
          <RadixPopover.Content collisionPadding={2} sideOffset={8}>
            <div onMouseEnter={() => setUseKeys(false)}>
              {isOpen && (
                <DropDownItemsMenu
                  options={options}
                  dropdownRef={dropdownRef}
                  selectedIndex={selectedIndex}
                  setSelectedIndex={setSelectedIndex}
                  onCreateClick={onCreateClick}
                  isOpen={isOpen}
                  useKeys={useKeys}
                  setUseKeys={setUseKeys}
                  inputValue={inputValue}
                  classType={classType}
                  maxHeight={Math.max(above, below)}
                  width={width}
                  onItemSelect={handleItemSelected}
                />
              )}
            </div>
          </RadixPopover.Content>
        </RadixPopover.Portal>
      </DropDownStyled>
    </RadixPopover.Root>
  );
};

interface DropDownItemsMenuProps {
  dropdownRef: React.MutableRefObject<null>;
  options: string[];
  selectedIndex: number;
  setSelectedIndex: (index: number) => void;
  useKeys: boolean;
  setUseKeys: (useKeys: boolean) => void;
  inputValue: string;
  /** When the new option in the dropdown menu is selected */
  onCreateClick?: () => void;
  isOpen: boolean;
  /** URL of the Class. Used for showing the label for `onCreateClick` */
  classType?: string;
  maxHeight: number;
  width: number;
  onItemSelect: (item: string) => void;
}

/**
 * The actual Items of the dropdown are quite expensive to calculate, as they
 * require building a search index from potentially unfetched resources. That is
 * why this component is only rendered if needed
 */
function DropDownItemsMenu({
  dropdownRef,
  inputValue,
  isOpen,
  onCreateClick,
  options,
  selectedIndex,
  setSelectedIndex,
  setUseKeys,
  useKeys,
  classType,
  maxHeight,
  width,
  onItemSelect,
}: DropDownItemsMenuProps): JSX.Element | null {
  const selectedItemRef = useRef<HTMLLIElement>(null);
  const searchResults = useLocalSearch(inputValue, options);
  const showCreateOption = onCreateClick && !inputValue.startsWith('http');

  const items: Array<Hit | CreateOption> = [
    ...(showCreateOption ? [{ type: 'createOption' } as CreateOption] : []),
    ...searchResults,
  ];

  const klass = useResource(classType);
  const [classTypeTitle] = useTitle(klass);

  // Select the item
  useHotkeys(
    'enter',
    e => {
      e.preventDefault();
      const item = items[selectedIndex];

      if (isCreateOption(item)) {
        onCreateClick && onCreateClick();

        return;
      }

      if (selectedIndex > 0) {
        onItemSelect(item.item.subject);
      } else {
        onItemSelect(inputValue);
      }
    },
    { enabled: isOpen, enableOnTags: ['INPUT'] },
    [selectedIndex],
  );

  // Move up (or to bottom if at top)
  useHotkeys(
    'up',
    e => {
      e.preventDefault();
      setUseKeys(true);
      const newSelected =
        selectedIndex <= 0 ? items.length - 1 : selectedIndex - 1;
      setSelectedIndex(newSelected);
    },
    { enabled: isOpen, enableOnTags: ['INPUT'] },
    [selectedIndex],
  );

  // Move down (or to top if at bottom)
  useHotkeys(
    'down',
    e => {
      e.preventDefault();
      setUseKeys(true);
      const newSelected =
        selectedIndex === items.length - 1 ? 0 : selectedIndex + 1;
      setSelectedIndex(newSelected);

      return false;
    },
    { enabled: isOpen, enableOnTags: ['INPUT'] },
    [selectedIndex],
  );

  useEffect(() => {
    selectedItemRef.current?.scrollIntoView({ block: 'nearest' });
  }, [selectedIndex]);

  if (!items || items.length === 0) {
    return null;
  }

  return (
    <DropDownWrapper ref={dropdownRef} height={maxHeight} width={width}>
      <StyledScrollArea height={maxHeight}>
        {items.map((item, index) => {
          if (isCreateOption(item)) {
            return (
              <DropDownItem
                onClick={onCreateClick}
                key={inputValue}
                useKeys={useKeys}
                selected={index === selectedIndex}
                ref={index === selectedIndex ? selectedItemRef : null}
              >
                Create {classType ? classTypeTitle : 'new item'}:{' '}
                <NewItemName>{inputValue}</NewItemName>
              </DropDownItem>
            );
          }

          return (
            <DropDownItem
              onClick={() => onItemSelect(item.item.subject)}
              key={item.item.subject}
              selected={index === selectedIndex}
              useKeys={useKeys}
              ref={index === selectedIndex ? selectedItemRef : null}
            >
              <ResourceLine subject={item.item.subject} />
            </DropDownItem>
          );
        })}
      </StyledScrollArea>
    </DropDownWrapper>
  );
}

/** A wrapper for all dropdown items */
const ResourceInputOverlayWrapper = styled.div`
  position: relative;
  display: flex;
  flex: 1;
`;

/** A wrapper all dropdown items */
const DropDownStyled = styled.div`
  position: relative;
  flex: 1;
`;

interface StyledScrollAreaProps {
  height: number;
}

const StyledScrollArea = styled(ScrollArea)<StyledScrollAreaProps>`
  height: min(calc(${p => p.height}px - 2rem), 30rem);
  width: var(--dropdown-width);
  overflow-x: hidden;
`;

interface DropdownWrapperProps {
  height: number;
  width: number;
}

/** A wrapper all dropdown items */
const DropDownWrapper = styled.ul<DropdownWrapperProps>`
  display: flex;
  flex-direction: column;
  background-color: ${props => props.theme.colors.bg};
  border: solid 1px ${props => props.theme.colors.bg2};
  border-radius: ${props => props.theme.radius};
  box-shadow: ${props => props.theme.boxShadowSoft};
  max-height: min(calc(${p => p.height}px - 2rem), 30rem);
  contain: paint;
  --dropdown-width: ${p => p.width}px;
  width: var(--dropdown-width);
  min-width: 10rem;
`;

interface DropDownItemProps {
  selected?: boolean;
  useKeys?: boolean;
}

/** A wrapper all dropdown items */
const DropDownItem = styled.li<DropDownItemProps>`
  display: flex;
  width: var(--dropdown-width);
  overflow-x: hidden;
  flex-direction: row;
  border-bottom: solid 1px ${props => props.theme.colors.bg2};
  cursor: pointer;
  margin: 0;
  white-space: nowrap;
  padding: 0.3rem;

  ${props =>
    props.selected &&
    css`
      background-color: ${p => p.theme.colors.main};
      color: ${p => p.theme.colors.bg};

      & ${ResourceLineDescription} {
        color: ${p => p.theme.colors.bg};
      }
    `}

  ${props =>
    !props.useKeys &&
    css`
      &:hover,
      &:active,
      &:focus {
        background-color: ${p => p.theme.colors.main};
        color: ${p => p.theme.colors.bg};

        & ${ResourceLineDescription} {
          color: ${p => p.theme.colors.bg};
        }
      }
    `}
`;

/** A wrapper for wrapping around the dropdown if you want it tiny */
export const DropDownMini = styled.div`
  display: inline-flex;
  margin-bottom: 1rem;
  flex: 1;
  max-width: 20rem;
`;

const NewItemName = styled.span`
  font-style: italic;
  margin-left: 1ch;
`;

const StyledInputOverlay = styled(InputOverlay)`
  span {
    width: 100%;
    height: 2rem;
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
`;
