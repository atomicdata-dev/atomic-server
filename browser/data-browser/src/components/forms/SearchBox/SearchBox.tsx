import { useCallback, useContext, useEffect, useRef, useState } from 'react';
import { styled } from 'styled-components';
import { removeCachedSearchResults, useResource, useStore } from '@tomic/react';
import { DropdownPortalContext } from '../../Dropdown/dropdownContext';
import * as RadixPopover from '@radix-ui/react-popover';
import { SearchBoxWindow } from './SearchBoxWindow';
import { FaTimes } from 'react-icons/fa';
import { ErrorChip } from '../ErrorChip';
import { useValidation } from '../formValidation/useValidation';

interface SearchBoxProps {
  autoFocus?: boolean;
  value: string | undefined;
  isA?: string;
  scopes?: string[];
  placeholder?: string;
  disabled?: boolean;
  required?: boolean;
  className?: string;
  onChange: (value: string | undefined) => void;
  onCreateItem?: (name: string) => void;
  onClose?: () => void;
}

export function SearchBox({
  autoFocus,
  value,
  isA,
  scopes,
  placeholder,
  disabled,
  required,
  className,
  children,
  onChange,
  onCreateItem,
  onClose,
}: React.PropsWithChildren<SearchBoxProps>): JSX.Element {
  const store = useStore();
  const selectedResource = useResource(value);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const [inputValue, setInputValue] = useState('');
  const typeResource = useResource(isA);
  const [open, setOpen] = useState(false);
  const containerRef = useContext(DropdownPortalContext);
  const [justFocussed, setJustFocussed] = useState(false);

  const [error, setError, handleBlur] = useValidation();

  const placeholderText =
    placeholder ??
    `Search for a ${isA ? typeResource.title : 'resource'} or enter a URL...`;

  const handleExit = useCallback(
    (lostFocus: boolean) => {
      setOpen(false);
      handleBlur();

      if (!lostFocus) {
        triggerRef.current?.focus();
      } else {
        setJustFocussed(false);
      }

      onClose?.();
    },
    [onClose],
  );

  const handleSelect = useCallback(
    (newValue: string) => {
      try {
        new URL(newValue);
        onChange(newValue);
        setInputValue('');
      } catch (e) {
        console.error(e);
        // not a URL
      }

      handleExit(false);
      removeCachedSearchResults(store);
    },
    [inputValue, onChange, handleExit, store],
  );

  const handleTriggerFocus = () => {
    if (justFocussed) {
      setJustFocussed(false);

      return;
    }

    setOpen(true);
    setJustFocussed(true);
  };

  useEffect(() => {
    if (!!required && !value) {
      setError('Required');

      return;
    }

    if (selectedResource.error) {
      setError('Invalid Resource', true);

      return;
    }

    setError(undefined);
  }, [setError, required, value, selectedResource]);

  return (
    <RadixPopover.Root open={open}>
      <RadixPopover.Anchor>
        <TriggerButtonWrapper
          disabled={!!disabled}
          className={className}
          invalid={!!error}
        >
          <TriggerButton
            autoFocus={autoFocus}
            disabled={disabled}
            ref={triggerRef}
            tabIndex={0}
            $empty={inputValue.length === 0}
            onFocus={handleTriggerFocus}
            onClick={() => {
              setOpen(true);
              setJustFocussed(true);
            }}
          >
            {value ? (
              <ResourceTitle>
                {selectedResource.error
                  ? selectedResource.getSubject()
                  : selectedResource.title}
              </ResourceTitle>
            ) : (
              <PlaceholderText>{placeholderText}</PlaceholderText>
            )}
          </TriggerButton>
          {value && (
            <SearchBoxButton
              title='clear'
              onClick={() => onChange(undefined)}
              type='button'
            >
              <FaTimes />
            </SearchBoxButton>
          )}
          {children}
          {error && (
            <PositionedErrorChip noMovement>{error}</PositionedErrorChip>
          )}
        </TriggerButtonWrapper>
      </RadixPopover.Anchor>
      <RadixPopover.Portal container={containerRef.current}>
        <RadixPopover.Content align='start'>
          {open && (
            <SearchBoxWindow
              searchValue={inputValue}
              onChange={setInputValue}
              scopes={scopes}
              isA={isA}
              placeholder={placeholderText}
              triggerRef={triggerRef}
              onExit={handleExit}
              onSelect={handleSelect}
              onCreateItem={onCreateItem}
            />
          )}
        </RadixPopover.Content>
      </RadixPopover.Portal>
    </RadixPopover.Root>
  );
}

const TriggerButton = styled.button<{ $empty: boolean }>`
  display: flex;
  align-items: center;
  padding: 0.5rem;
  border-radius: ${props => props.theme.radius};
  background-color: ${props => props.theme.colors.bg};
  border: none;
  text-align: start;
  height: 2rem;
  width: 100%;
  overflow: hidden;
  cursor: text;
  color: ${p => (p.$empty ? p.theme.colors.textLight : p.theme.colors.text)};

  &:disabled {
    background-color: ${props => props.theme.colors.bg1};
  }
`;

const TriggerButtonWrapper = styled.div<{
  invalid: boolean;
  disabled: boolean;
}>`
  --search-box-hightlight: ${p =>
    p.invalid ? p.theme.colors.alert : p.theme.colors.main};
  display: flex;
  position: relative;
  border: 1px solid ${props => props.theme.colors.bg2};
  border-radius: ${props => props.theme.radius};
  &:hover,
  &:focus-within {
    border-color: ${p =>
      p.disabled ? 'none' : 'var(--search-box-hightlight)'};
  }
`;

const ResourceTitle = styled.span`
  color: var(--search-box-hightlight);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const PlaceholderText = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

export const SearchBoxButton = styled.button`
  background-color: ${p => p.theme.colors.bg};
  border: none;
  border-left: 1px solid ${p => p.theme.colors.bg2};
  display: flex;
  align-items: center;
  padding: 0.5rem;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;

  &:hover,
  &:focus-visible {
    color: var(--search-box-hightlight);
    background-color: ${p => p.theme.colors.bg1};
    border-color: var(--search-box-hightlight);
  }

  &:last-of-type {
    border-top-right-radius: ${p => p.theme.radius};
    border-bottom-right-radius: ${p => p.theme.radius};
  }
`;

const PositionedErrorChip = styled(ErrorChip)`
  position: absolute;
  top: 2rem;
  z-index: 10;
`;
