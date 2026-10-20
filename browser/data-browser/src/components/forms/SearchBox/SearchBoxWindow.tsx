import {
  core,
  dataBrowser,
  useResources,
  useServerSearch,
  useStore,
} from '@tomic/react';
import {
  ClipboardEventHandler,
  KeyboardEventHandler,
  RefObject,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
} from 'react';
import { FaMagnifyingGlass } from 'react-icons/fa6';
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
import { addIf } from '../../../helpers/addIf';
import { Row } from '../../Row';
import React from 'react';
import { externalOrigin, searchLoadedExternal } from './loadedExternal';

/**
 * Options shown at the top of the results when the `isA` prop matches a key in this object.
 */
// Typing one of these starts a subject, not a search.
const SUBJECT_PREFIXES = ['http:', 'https:', 'atomic:', 'did:'];

const STANDARD_OPTIONS: Record<string, string[]> = {
  [core.classes.property]: [
    core.properties.name,
    core.properties.description,
    core.properties.shortname,
    dataBrowser.properties.image,
  ],
};

enum OptionType {
  CreateOption,
  StandardOption,
  Result,
}

type Option = {
  type: OptionType;
  data: string;
};

/**
 * Classes whose search also looks at external resources the store has already
 * fetched, e.g. shared classes published outside the drive. The server search
 * only covers the drive and atomicdata.dev.
 */
const INCLUDE_LOADED_EXTERNAL: string[] = [core.classes.class];

const BOX_HEIGHT_REM = 20;

interface SearchBoxWindowProps {
  searchValue: string;
  isA?: string;
  scopes?: string[];
  placeholder?: string;
  allowsOnly?: string[];
  triggerRef: RefObject<HTMLButtonElement | null>;
  onExit: (lostFocus: boolean) => void;
  onChange: (value: string) => void;
  onSelect: (value: string) => void;
  onCreateItem?: (name: string, isA?: string) => void;
}

/**
 * The window that opens when the searchbox is focussed.
 * It handles searching, both locally and on the server.
 */
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
  const store = useStore();

  const [index, setIndex] = useState<number | undefined>(undefined);
  const [results, setResults] = useState<string[]>([]);
  const [searchError, setSearchError] = useState<Error | undefined>();
  const [valueIsURL, setValueIsURL] = useState(false);

  const { below } = useAvailableSpace(true, triggerRef);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const { titleProp, classTitle } = useTitlePropOfClass(isA);

  const isAboveTrigger = below < remToPixels(BOX_HEIGHT_REM);

  const showCreateOption =
    !!onCreateItem && !!searchValue && !valueIsURL && !allowsOnly;

  const standardOptions = useMemo(() => {
    if (!searchValue && isA && isA in STANDARD_OPTIONS) {
      return STANDARD_OPTIONS[isA];
    }

    return [];
  }, [isA, searchValue]);

  const serverUrl = store.getServerUrl();

  // Externals are only merged into an unscoped server search: a caller that
  // passes `scopes` or `allowsOnly` asked for exactly those.
  const loadedExternal = useMemo(
    () =>
      isA && !scopes && !allowsOnly && INCLUDE_LOADED_EXTERNAL.includes(isA)
        ? searchLoadedExternal(
            store.resources,
            searchValue,
            isA,
            serverUrl,
          ).filter(subject => !results.includes(subject))
        : [],
    [isA, scopes, allowsOnly, store, searchValue, serverUrl, results],
  );

  const options: Option[] = useMemo(
    () => [
      ...addIf(showCreateOption, {
        type: OptionType.CreateOption,
        data: '',
      }),
      ...standardOptions.map(option => ({
        type: OptionType.StandardOption,
        data: option,
      })),
      ...results.map(result => ({ type: OptionType.Result, data: result })),
      ...loadedExternal.map(result => ({
        type: OptionType.Result,
        data: result,
      })),
    ],
    [showCreateOption, standardOptions, results, loadedExternal],
  );

  const selectedIndex =
    index !== undefined ? loopingIndex(index, options.length) : undefined;

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

  const pickSelectedItem = (override?: number) => {
    if (selectedIndex === undefined && override === undefined) {
      onSelect(searchValue);

      return;
    }

    const selected = options[override! ?? selectedIndex!];

    // No results to pick from: take what was typed (a pasted subject).
    if (!selected) {
      if (searchValue) onSelect(searchValue);

      return;
    }

    // The selected option is a "Create ..." option.
    if (selected.type === OptionType.CreateOption) {
      createItem(searchValue);

      return;
    }

    // The selected option is a standard option or a search result.
    onSelect(selected.data);
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
    if (SUBJECT_PREFIXES.some(prefix => e.target.value.startsWith(prefix))) {
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
    <Wrapper
      onBlur={handleBlur}
      ref={wrapperRef}
      $above={isAboveTrigger}
      onMouseLeave={() => setIndex(undefined)}
    >
      <SearchInputWrapper>
        <FaMagnifyingGlass />
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
        {!searchValue && options.length === 0 && (
          <CenteredMessage>Start Searching</CenteredMessage>
        )}
        <StyledScrollArea>
          <List>
            {options.map((option, i) => {
              let line = <></>;

              if (option.type === OptionType.CreateOption) {
                line = (
                  <ResultLine
                    selected={selectedIndex === 0}
                    onMouseOver={() => handleMouseMove(0)}
                    onClick={() => createItem(searchValue)}
                  >
                    {titleProp ? (
                      <Row gap='0.5ch'>
                        Create{' '}
                        <CreateLineInputText>{searchValue}</CreateLineInputText>
                      </Row>
                    ) : (
                      `Create new ${classTitle ?? 'resource'}`
                    )}
                  </ResultLine>
                );
              } else {
                line = (
                  <ResourceResultLine
                    subject={option.data}
                    origin={externalOrigin(option.data, serverUrl)}
                    selected={i === selectedIndex}
                    onMouseOver={() => handleMouseMove(i)}
                    onClick={() => {
                      // On mobile the item is not selected by hover so we need to force pickSelectedItem to pick this one.
                      pickSelectedItem(i);
                    }}
                  />
                );
              }

              // Show a divider if the next option is of a different type. But not on the last option.
              const showDivider =
                options[i + 1] !== undefined &&
                option.type !== options[i + 1].type;

              return (
                <React.Fragment
                  key={
                    option.type === OptionType.CreateOption
                      ? 'create option'
                      : option.data
                  }
                >
                  {line}
                  {showDivider && <Divider />}
                </React.Fragment>
              );
            })}
          </List>
          {!!searchValue &&
            results.length === 0 &&
            loadedExternal.length === 0 && (
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
      parents: scopes ?? [
        drive,
        // We don't want to show atomicdata.dev results when there are standard defined options.
        ...addIf(!!isA && !(isA in STANDARD_OPTIONS), 'https://atomicdata.dev'),
      ],
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
  container: searchbox / inline-size;
  flex: 1;
  border: solid 1px ${p => p.theme.colors.bg2};
  height: calc(100% - 2rem);
  overflow: hidden;
`;

const List = styled.ul`
  display: grid;
  grid-template-columns: 20ch auto;
  column-gap: 1ch;
  overflow: hidden;
  width: calc(100cqw);
  margin-bottom: 0;

  @container (max-width: 520px) {
    grid-template-columns: 1fr;
  }
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
  left: 0;
  animation: ${fadeIn} 0.2s ease-in-out;

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

const Divider = styled.div`
  border-top: 1px solid ${props => props.theme.colors.bg2};
  grid-column: 1/3;

  @container (max-width: 520px) {
    grid-column: 1/2;
  }
`;
