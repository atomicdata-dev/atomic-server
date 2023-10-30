import { core, useServerSearch } from '@tomic/react';
import React, { useMemo, useState } from 'react';
import { styled, css } from 'styled-components';
import { ResourceResultLine, ResultLine } from './ResultLine';
import { fadeIn } from '../../../helpers/commonAnimations';
import { ScrollArea } from '../../ScrollArea';
import { loopingIndex } from '../../../helpers/loopingIndex';
import { focusOffsetElement } from '../../../helpers/focusOffsetElement';
import { isURL } from '../../../helpers/isURL';
import { useAvailableSpace } from '../hooks/useAvailableSpace';
import { remToPixels } from '../../../helpers/remToPixels';
import { useSettings } from '../../../helpers/AppSettings';

const BOX_HEIGHT_REM = 20;

interface SearchBoxWindowProps {
  searchValue: string;
  isA?: string;
  scopes?: string[];
  placeholder?: string;
  triggerRef: React.RefObject<HTMLButtonElement>;
  onExit: (lostFocus: boolean) => void;
  onChange: (value: string) => void;
  onSelect: (value: string) => void;
  onCreateItem?: (name: string) => void;
}

export function SearchBoxWindow({
  searchValue,
  onChange,
  isA,
  scopes,
  placeholder,
  triggerRef,
  onExit,
  onSelect,
  onCreateItem,
}: SearchBoxWindowProps): JSX.Element {
  const { drive } = useSettings();
  const [realIndex, setIndex] = useState<number | undefined>(undefined);
  const { below } = useAvailableSpace(true, triggerRef);
  const wrapperRef = React.useRef<HTMLDivElement>(null);

  const searchOptions = useMemo(
    () => ({
      filters: {
        ...(isA ? { [core.properties.isA]: isA } : {}),
      },
      parents: scopes ?? [drive, 'https://atomicdata.dev'],
    }),
    [isA, scopes],
  );

  const { results, error: searchError } = useServerSearch(
    searchValue,
    searchOptions,
  );

  const isAboveTrigger = below < remToPixels(BOX_HEIGHT_REM);

  const offset = onCreateItem ? 1 : 0;

  const selectedIndex =
    realIndex !== undefined
      ? loopingIndex(realIndex, results.length + offset)
      : undefined;

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      pickSelectedItem();

      return;
    }

    if (e.key === 'Escape') {
      onExit(false);

      return;
    }

    if (e.key === 'Tab' && e.shiftKey) {
      e.preventDefault();
      focusOffsetElement(-1, triggerRef.current!);

      return;
    }

    if (e.key === 'Tab') {
      e.preventDefault();
      focusOffsetElement(1, triggerRef.current!);

      return;
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault();

      setIndex(prev => {
        if (prev === undefined) {
          return 0;
        }

        return prev + 1;
      });

      return;
    }

    if (e.key === 'ArrowUp') {
      e.preventDefault();

      setIndex(prev => (prev ?? 0) - 1);

      return;
    }

    setIndex(undefined);
  };

  const handleMouseMove = (i: number) => {
    setIndex(i);
  };

  const pickSelectedItem = () => {
    if (selectedIndex === undefined) {
      onSelect(searchValue);

      return;
    }

    if (selectedIndex === 0 && onCreateItem) {
      onCreateItem(searchValue);

      return;
    }

    onSelect(results[selectedIndex - offset]);
  };

  const handleBlur = () => {
    requestAnimationFrame(() => {
      if (!wrapperRef.current?.contains(document.activeElement)) {
        onExit(true);
      }
    });
  };

  const handlePaste: React.ClipboardEventHandler<HTMLInputElement> = e => {
    const data = e.clipboardData.getData('text');

    if (isURL(data)) {
      e.preventDefault();
      onSelect(data);
    }
  };

  if (searchError) {
    return (
      <Wrapper onBlur={handleBlur} ref={wrapperRef} $above={isAboveTrigger}>
        <CenteredMessage>Error: {searchError.message}</CenteredMessage>
      </Wrapper>
    );
  }

  return (
    <Wrapper onBlur={handleBlur} ref={wrapperRef} $above={isAboveTrigger}>
      <Input
        autoFocus
        placeholder={placeholder}
        value={searchValue}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
          onChange(e.target.value)
        }
        onKeyDown={handleKeyDown}
        onPaste={handlePaste}
      />
      <ResultBox data-testid='searchbox-results'>
        {!searchValue && <CenteredMessage>Start Searching</CenteredMessage>}
        <StyledScrollArea>
          <ul>
            {onCreateItem ? (
              <ResultLine
                selected={selectedIndex === 0}
                onMouseOver={() => handleMouseMove(0)}
                onClick={() => onCreateItem(searchValue)}
              >
                Create {searchValue}
              </ResultLine>
            ) : null}
            {results.map((result, i) => (
              <ResourceResultLine
                key={result}
                subject={result}
                selected={i + offset === selectedIndex}
                onMouseOver={() => handleMouseMove(i + offset)}
                onClick={pickSelectedItem}
              />
            ))}
          </ul>
          {!!searchValue && results.length === 0 && (
            <CenteredMessage>No Results</CenteredMessage>
          )}
        </StyledScrollArea>
      </ResultBox>
    </Wrapper>
  );
}

const Input = styled.input`
  border: solid 1px ${p => p.theme.colors.bg2};
  padding: 0.5rem;
  height: var(--radix-popover-trigger-height);
  width: 100%;

  &:focus-visible {
    border-color: ${p => p.theme.colors.main};
    outline: none;
  }
`;

const ResultBox = styled.div`
  flex: 1;
  border: solid 1px ${p => p.theme.colors.bg2};

  height: calc(100% - 2rem);
  overflow: hidden;
`;

const Wrapper = styled.div<{ $above: boolean }>`
  display: flex;

  background-color: ${p => p.theme.colors.bg};
  border-radius: ${p => p.theme.radius};
  box-shadow: ${p => p.theme.boxShadowSoft};
  width: 100%;
  height: ${BOX_HEIGHT_REM}rem;
  position: absolute;
  width: var(--radix-popover-trigger-width);
  ${({ $above, theme }) =>
    $above
      ? css`
          bottom: 0;
          flex-direction: column-reverse;

          ${Input} {
            border-bottom-left-radius: ${theme.radius};
            border-bottom-right-radius: ${theme.radius};
          }

          ${ResultBox} {
            border-bottom: none;
            border-top-left-radius: ${p => p.theme.radius};
            border-top-right-radius: ${p => p.theme.radius};
          }
        `
      : css`
          top: calc(var(--radix-popover-trigger-height) * -1);
          flex-direction: column;

          ${Input} {
            border-top-left-radius: ${theme.radius};
            border-top-right-radius: ${theme.radius};
          }

          ${ResultBox} {
            border-top: none;
            border-bottom-left-radius: ${p => p.theme.radius};
            border-bottom-right-radius: ${p => p.theme.radius};
          }
        `}
  left: 0;

  animation: ${fadeIn} 0.2s ease-in-out;
`;
const CenteredMessage = styled.div`
  display: grid;
  place-items: center;
  height: 100%;
  width: 100%;
  color: ${p => p.theme.colors.textLight};
`;

const StyledScrollArea = styled(ScrollArea)`
  overflow: hidden;
  height: 100%;
`;
