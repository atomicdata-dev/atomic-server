import { core, useResources, useServerSearch } from '@tomic/react';
import {
  ClipboardEventHandler,
  KeyboardEventHandler,
  RefObject,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { FaSearch } from 'react-icons/fa';
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
import { QuickScore } from 'quick-score';
import { useTitlePropOfClass } from '../ResourceSelector/useTitlePropOfClass';
import { stringToSlug } from '../../../helpers/stringToSlug';

const BOX_HEIGHT_REM = 20;

interface SearchBoxWindowProps {
  searchValue: string;
  isA?: string;
  scopes?: string[];
  placeholder?: string;
  allowsOnly?: string[];
  triggerRef: RefObject<HTMLButtonElement>;
  onExit: (lostFocus: boolean) => void;
  onChange: (value: string) => void;
  onSelect: (value: string) => void;
  onCreateItem?: (name: string, isA?: string) => void;
}

export function SearchBoxWindow({
  searchValue,
  onChange,
  isA,
  scopes,
  placeholder,
  triggerRef,
  allowsOnly,
  onExit,
  onSelect,
  onCreateItem,
}: SearchBoxWindowProps): JSX.Element {
  const { drive } = useSettings();

  const [realIndex, setIndex] = useState<number | undefined>(undefined);
  const [results, setResults] = useState<string[]>([]);
  const [searchError, setSearchError] = useState<Error | undefined>();
  const [valueIsURL, setValueIsURL] = useState(false);

  const { below } = useAvailableSpace(true, triggerRef);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const { titleProp, classTitle } = useTitlePropOfClass(isA);

  const isAboveTrigger = below < remToPixels(BOX_HEIGHT_REM);

  const showCreateOption =
    onCreateItem && searchValue && !valueIsURL && !allowsOnly;

  const offset = showCreateOption ? 1 : 0;

  const selectedIndex =
    realIndex !== undefined
      ? loopingIndex(realIndex, results.length + offset)
      : undefined;

  const handleKeyDown: KeyboardEventHandler<HTMLInputElement> = e => {
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

  const createItem = (name: string) => {
    if (!onCreateItem) {
      throw new Error('No onCreateItem function provided');
    }

    onCreateItem(name, isA);
  };

  const pickSelectedItem = () => {
    if (selectedIndex === undefined) {
      onSelect(searchValue);

      return;
    }

    if (selectedIndex === 0 && showCreateOption) {
      createItem(searchValue);

      return;
    }

    onSelect(results[selectedIndex - offset]);
  };

  const handleResults = useCallback((res: string[], error?: Error) => {
    setResults(res);
    setSearchError(error);
  }, []);

  const handleBlur = () => {
    requestAnimationFrame(() => {
      if (!wrapperRef.current?.contains(document.activeElement)) {
        onExit(true);
      }
    });
  };

  const handlePaste: ClipboardEventHandler<HTMLInputElement> = e => {
    const data = e.clipboardData.getData('text');

    if (isURL(data)) {
      e.preventDefault();
      onSelect(data);
    }
  };

  const handleChange: React.ChangeEventHandler<HTMLInputElement> = e => {
    if (
      e.target.value.startsWith('http:') ||
      e.target.value.startsWith('https:')
    ) {
      onChange(e.target.value);
      setValueIsURL(true);

      return;
    }

    if (titleProp === core.properties.shortname) {
      onChange(stringToSlug(e.target.value));
    } else {
      onChange(e.target.value);
    }

    setValueIsURL(false);
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
      <SearchInputWrapper>
        <FaSearch />
        <Input
          autoFocus
          placeholder={placeholder}
          value={searchValue}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          onPaste={handlePaste}
        />
      </SearchInputWrapper>
      <ResultBox data-testid='searchbox-results'>
        {!searchValue && results.length === 0 && (
          <CenteredMessage>Start Searching</CenteredMessage>
        )}
        <StyledScrollArea>
          <ul>
            {showCreateOption ? (
              <ResultLine
                selected={selectedIndex === 0}
                onMouseOver={() => handleMouseMove(0)}
                onClick={() => createItem(searchValue)}
              >
                {titleProp ? (
                  <>
                    Create{' '}
                    <CreateLineInputText>{searchValue}</CreateLineInputText>
                  </>
                ) : (
                  `Create new ${classTitle ?? 'resource'}`
                )}
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
      {allowsOnly ? (
        <LocalSearchUnit
          searchValue={searchValue}
          allowsOnly={allowsOnly}
          onResult={handleResults}
        />
      ) : (
        <ServerSearchUnit
          drive={drive}
          isA={isA}
          scopes={scopes}
          searchValue={searchValue}
          onResult={handleResults}
        />
      )}
    </Wrapper>
  );
}

interface SearchUnitProps {
  searchValue: string;
  onResult: (result: string[], error?: Error) => void;
}

interface ServerSearchUnitProps extends SearchUnitProps {
  isA?: string;
  scopes?: string[];
  drive: string;
}

interface LocalSearchUnitProps extends SearchUnitProps {
  allowsOnly: string[];
}

const ServerSearchUnit = ({
  searchValue,
  isA,
  scopes,
  drive,
  onResult,
}: ServerSearchUnitProps) => {
  const searchOptions = useMemo(
    () => ({
      filters: {
        ...(isA ? { [core.properties.isA]: isA } : {}),
      },
      parents: scopes ?? [drive, 'https://atomicdata.dev'],
      // If a classtype is given we want to prefill the searchbox with data.
      allowEmptyQuery: !!isA,
    }),
    [isA, scopes],
  );

  const { results, error } = useServerSearch(searchValue, searchOptions);

  useEffect(() => {
    onResult(results, error);
  }, [results, error, onResult]);

  return null;
};

const LocalSearchUnit = ({
  searchValue,
  allowsOnly,
  onResult,
}: LocalSearchUnitProps) => {
  const resources = useResources(allowsOnly);

  const quickScore = useMemo(() => {
    const values = Array.from(resources.entries()).map(
      ([subject, resource]) => ({
        title: resource.title,
        subject,
      }),
    );

    return new QuickScore(values, ['title']);
  }, [resources]);

  useEffect(() => {
    if (searchValue === '') {
      onResult(allowsOnly);

      return;
    }

    const results = quickScore
      .search(searchValue)
      .map(result => result.item.subject);

    onResult(results);
  }, [searchValue, quickScore]);

  return null;
};

const SearchInputWrapper = styled.div`
  display: flex;
  flex-direction: row;
  align-items: center;
  border: solid 1px ${p => p.theme.colors.bg2};
  height: var(--radix-popover-trigger-height);
  padding-inline-start: 0.5rem;
  width: 100%;

  & svg {
    color: ${p => p.theme.colors.textLight};
  }
  &:focus-within {
    border-color: ${p => p.theme.colors.main};
    box-shadow: 0 0 0 1px ${p => p.theme.colors.main};
    outline: none;
  }
`;

const Input = styled.input`
  background-color: transparent;
  color: ${p => p.theme.colors.text};
  padding: 0.5rem;
  height: 100%;
  flex: 1;
  border: none;
  &:focus-visible {
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

          ${SearchInputWrapper}, ${Input} {
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

          ${SearchInputWrapper}, ${Input} {
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

const CreateLineInputText = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-style: italic;
`;
