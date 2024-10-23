import {
  MouseEventHandler,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react';
import { css, styled } from 'styled-components';
import { removeCachedSearchResults, useResource, useStore } from '@tomic/react';
import { DropdownPortalContext } from '../../Dropdown/dropdownContext';
import * as RadixPopover from '@radix-ui/react-popover';
import { SearchBoxWindow } from './SearchBoxWindow';
import { FaExternalLinkAlt, FaSearch, FaTimes } from 'react-icons/fa';
import { ErrorChip } from '../ErrorChip';
import { constructOpenURL } from '../../../helpers/navigation';
import { useNavigateWithTransition } from '../../../hooks/useNavigateWithTransition';
import { SearchBoxButton } from './SearchBoxButton';
import {
  SB_BACKGROUND,
  SB_BOTTOM_RADIUS,
  SB_HIGHLIGHT,
  SB_TOP_RADIUS,
} from './searchboxVars';
import { useDialogTreeContext } from '../../Dialog/dialogContext';
import { useResourceFormContext } from '../ResourceFormContext';

export type OnResourceError = (hasError: boolean) => void;

interface SearchBoxProps {
  autoFocus?: boolean;
  value: string | undefined;
  isA?: string;
  scopes?: string[];
  allowsOnly?: string[];
  placeholder?: string;
  disabled?: boolean;
  required?: boolean;
  className?: string;
  prefix?: React.ReactNode;
  hideClearButton?: boolean;
  visualError?: string;
  id?: string;
  onChange: (value: string | undefined) => void;
  onCreateItem?: (name: string, isA?: string) => void;
  onClose?: () => void;
  onResourceError?: OnResourceError;
}

export function SearchBox({
  autoFocus,
  value,
  isA,
  scopes,
  placeholder,
  disabled,
  className,
  children,
  prefix,
  hideClearButton,
  allowsOnly,
  visualError,
  id,
  onChange,
  onCreateItem,
  onClose,
  onResourceError,
}: React.PropsWithChildren<SearchBoxProps>): JSX.Element {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const selectedResource = useResource(value);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const [inputValue, setInputValue] = useState('');
  const typeResource = useResource(isA);
  const [open, setOpen] = useState(false);
  const containerRef = useContext(DropdownPortalContext);
  const [justFocussed, setJustFocussed] = useState(false);
  const { inDialog } = useDialogTreeContext();
  const { inResourceForm } = useResourceFormContext();

  const disableGotoButton = inDialog && inResourceForm;

  const placeholderText =
    placeholder ??
    `Search for a ${isA ? typeResource.title : 'resource'} or enter a URL...`;

  const handleExit = useCallback(
    (lostFocus: boolean) => {
      setOpen(false);

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
    if (!selectedResource) {
      return;
    }

    if (selectedResource.error) {
      onResourceError?.(true);

      return;
    }

    onResourceError?.(false);
  }, [onResourceError, selectedResource]);

  const openLink =
    !value || selectedResource.error
      ? '#'
      : constructOpenURL(selectedResource.subject);

  const navigateToSelectedResource: MouseEventHandler<
    HTMLButtonElement
  > = e => {
    e.preventDefault();
    navigate(openLink);
  };

  const title = selectedResource.error
    ? selectedResource.subject
    : selectedResource.title;

  return (
    <RadixPopover.Root open={open}>
      <RadixPopover.Anchor>
        <TriggerButtonWrapper
          disabled={!!disabled}
          className={className}
          open={open}
          invalid={!!visualError}
        >
          {prefix}
          <TriggerButton
            type='button'
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
            id={id}
          >
            {value ? (
              <ResourceTitle>{title}</ResourceTitle>
            ) : (
              <>
                <FaSearch />
                <PlaceholderText>{placeholderText}</PlaceholderText>
              </>
            )}
          </TriggerButton>
          {value && (
            <>
              {!disabled && !hideClearButton && (
                <SearchBoxButton
                  ephimeral
                  title='clear'
                  onClick={() => onChange(undefined)}
                  type='button'
                >
                  <FaTimes />
                </SearchBoxButton>
              )}

              <SearchBoxButton
                disabled={disableGotoButton}
                title={`go to ${title}`}
                onClick={navigateToSelectedResource}
                type='button'
              >
                <FaExternalLinkAlt />
              </SearchBoxButton>
            </>
          )}
          {children}
          {visualError && (
            <PositionedErrorChip noMovement>{visualError}</PositionedErrorChip>
          )}
        </TriggerButtonWrapper>
      </RadixPopover.Anchor>
      <RadixPopover.Portal container={containerRef.current}>
        <RadixPopover.Content align='start' avoidCollisions>
          {open && (
            <SearchBoxWindow
              searchValue={inputValue}
              onChange={setInputValue}
              scopes={scopes}
              isA={isA}
              placeholder={placeholderText}
              triggerRef={triggerRef}
              allowsOnly={allowsOnly}
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
  background: transparent;
  border: none;
  text-align: start;
  height: 2rem;
  gap: 0.5rem;
  width: 100%;
  overflow: hidden;
  cursor: text;
  color: ${p => (p.$empty ? p.theme.colors.textLight : p.theme.colors.text)};
`;

const TriggerButtonWrapper = styled.div<{
  invalid: boolean;
  disabled: boolean;
  open: boolean;
}>`
  ${SB_HIGHLIGHT.define(p =>
    p.invalid ? p.theme.colors.alert : p.theme.colors.main,
  )}

  max-width: 100cqw;

  display: flex;
  position: relative;
  border: 1px solid ${props => props.theme.colors.bg2};

  border-top-left-radius: ${p => SB_TOP_RADIUS.var(p.theme.radius)};
  border-top-right-radius: ${p => SB_TOP_RADIUS.var(p.theme.radius)};
  border-bottom-left-radius: ${p => SB_BOTTOM_RADIUS.var(p.theme.radius)};
  border-bottom-right-radius: ${p => SB_BOTTOM_RADIUS.var(p.theme.radius)};

  background-color: ${p => SB_BACKGROUND.var(p.theme.colors.bg)};

  &:disabled {
    background-color: ${props => props.theme.colors.bg1};
  }

  &:has(${TriggerButton}:hover(), ${TriggerButton}:focus-visible) {
  }
  &:hover,
  &:focus-visible {
    border-color: transparent;
    box-shadow: 0 0 0 2px ${SB_HIGHLIGHT.var()};
    ${p =>
      !p.open &&
      css`
        z-index: 1000;
      `}
  }
`;

const ResourceTitle = styled.span`
  color: ${SB_HIGHLIGHT.var()};
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const PlaceholderText = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const PositionedErrorChip = styled(ErrorChip)`
  position: absolute;
  top: 2rem;
  z-index: 1001;
`;
