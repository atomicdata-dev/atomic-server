import { useEffect, useRef, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { constructOpenURL } from '../../helpers/navigation';
import ResourceCard from '../../views/Card/ResourceCard';
import { dataBrowser, useServerSearch } from '@tomic/react';
import { ErrorLook } from '../../components/ErrorLook';
import { FaMagnifyingGlass } from 'react-icons/fa6';
import { useQueryScopeHandler } from '../../hooks/useQueryScope';
import { useSettings } from '../../helpers/AppSettings';
import { Column, Row } from '../../components/Row';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { base64StringToFilter } from './searchUtils';
import { InlineFormattedResourceList } from '../../components/InlineFormattedResourceList';
import { ErrorBoundary } from '../../views/ErrorPage';
import { useOnValueChange } from '@helpers/useOnValueChange';
import { Spinner } from '../../components/Spinner';
import { LoaderBlock } from '../../components/Loader';
import { useSearchOverlay } from '../../components/Searchbar/SearchOverlayContext';

const OverlayBackdrop = styled.div`
  position: fixed;
  inset: 0;
  z-index: ${p => p.theme.zIndex.searchOverlay};
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(6px);
  animation: fadeIn 100ms ease-out;

  @keyframes fadeIn {
    from {
      opacity: 0;
    }
    to {
      opacity: 1;
    }
  }
`;

const CommandPalettePanel = styled.div`
  position: fixed;
  top: 15vh;
  left: 50%;
  transform: translateX(-50%);
  z-index: ${p => p.theme.zIndex.searchOverlay};
  width: 100%;
  max-width: 38rem;
  max-height: 70vh;
  display: flex;
  flex-direction: column;
  background: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  box-shadow: ${p => p.theme.boxShadow};
  animation: slideIn 100ms ease-out;
  overflow: hidden;

  @keyframes slideIn {
    from {
      opacity: 0;
      transform: translateX(-50%) translateY(-12px);
    }
    to {
      opacity: 1;
      transform: translateX(-50%) translateY(0);
    }
  }
`;

const SearchInputWrapper = styled.div`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.875rem 1rem;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};

  svg {
    color: ${p => p.theme.colors.textLight};
    flex-shrink: 0;
  }
`;

const SearchInput = styled.input`
  flex: 1;
  background: transparent;
  border: none;
  outline: none;
  font-size: 1rem;
  color: ${p => p.theme.colors.text};
  font-family: inherit;

  &::placeholder {
    color: ${p => p.theme.colors.textLight};
  }
`;

const ShortcutHint = styled.kbd`
  background: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: 0.25rem;
  padding: 0.1rem 0.35rem;
  font-size: 0.7rem;
  color: ${p => p.theme.colors.textLight};
  font-family: inherit;
`;

const ResultsArea = styled.div`
  flex: 1;
  overflow-y: auto;
  padding: 0.5rem;

  &:empty {
    display: none;
  }
`;

ResultsArea.displayName = 'ResultsArea';

const HeadingRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.875rem 1rem;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  color: ${p => p.theme.colors.textLight};
  font-size: 0.875rem;
`;

const HeadingIcon = styled.span`
  display: flex;
  align-items: center;
`;

const SkeletonRow = styled(LoaderBlock)`
  height: 3.25rem;
  flex-shrink: 0;
`;

const TagHeading = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-weight: bold;
`;

const HelperMessage = styled.p`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.875rem;
  padding: 0.75rem 1rem;
  line-height: 1.5;
`;

const FooterRow = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.5rem 1rem;
  border-top: 1px solid ${p => p.theme.colors.bg2};
  font-size: 0.75rem;
  color: ${p => p.theme.colors.textLight};
`;

const FooterHints = styled.div`
  display: flex;
  gap: 1rem;

  span {
    display: flex;
    align-items: center;
    gap: 0.3rem;
  }
`;

/**
 * Command palette overlay — centered, with input built in.
 * Opens via Cmd+K, closes via Escape or backdrop click.
 */
export function SearchOverlay(): JSX.Element | null {
  const { isOpen, closeSearch, inputRef } = useSearchOverlay();

  useEffect(() => {
    if (isOpen && inputRef.current) {
      // Small delay to let animation start first
      const timer = setTimeout(() => inputRef.current?.focus(), 50);

      return () => clearTimeout(timer);
    }
  }, [isOpen, inputRef.current]);

  if (!isOpen) {
    return null;
  }

  return (
    <>
      <OverlayBackdrop onClick={closeSearch} />
      <CommandPalettePanel onClick={e => e.stopPropagation()}>
        <SearchOverlayContent closeSearch={closeSearch} />
      </CommandPalettePanel>
    </>
  );
}

function SearchOverlayContent({
  closeSearch,
}: {
  closeSearch: () => void;
}): JSX.Element {
  const {
    query,
    filters: filtersBase64,
    setQuery,
    inputRef,
  } = useSearchOverlay();
  const { drive } = useSettings();
  const { scope } = useQueryScopeHandler();
  const navigate = useNavigateWithTransition();

  const filters = filtersBase64 ? base64StringToFilter(filtersBase64) : {};
  const filterIsEmpty = Object.keys(filters).length === 0;
  const tags = (filters[dataBrowser.properties.tags] as string[]) ?? [];

  const [selectedIndex, setSelected] = useState(0);
  const { results, loading, error } = useServerSearch(query, {
    debounce: 0,
    parents: scope || drive,
    include: true,
    filters,
    allowEmptyQuery: !filterIsEmpty,
  });

  const resultsRef = useRef<HTMLDivElement | null>(null);

  // Sync query from context into the input
  useEffect(() => {
    if (inputRef.current && inputRef.current.value !== query) {
      inputRef.current.value = query;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, inputRef.current]);

  // Reset selection when results change
  useOnValueChange(() => {
    setSelected(0);
  }, [results]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setQuery(e.target.value);
    setSelected(0);
  };

  const handleSelectResult = () => {
    const selectedSubject = results[selectedIndex];

    if (selectedSubject) {
      (document.activeElement as HTMLInputElement | null)?.blur();
      const openURL = constructOpenURL(selectedSubject);
      navigate(openURL);
      closeSearch();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelected(prev =>
          prev === results.length - 1 ? results.length - 1 : prev + 1,
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelected(prev => (prev > 0 ? prev - 1 : 0));
        break;
      case 'Enter':
        e.preventDefault();
        handleSelectResult();
        break;
      case 'Escape':
        e.preventDefault();
        closeSearch();
        break;
    }
  };

  useEffect(() => {
    if (selectedIndex >= 0 && resultsRef.current) {
      const selectedEl = resultsRef.current.querySelector(
        `[data-index="${selectedIndex}"]`,
      ) as HTMLElement | null;
      selectedEl?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }, [selectedIndex]);

  let heading: string | undefined = 'No hits';

  if (!query && filterIsEmpty) {
    heading = undefined;
  }

  if (loading) {
    heading = 'Searching...';
  }

  const showHelperMessage = !query && filterIsEmpty;

  return (
    <ErrorBoundary>
      <SearchInputWrapper>
        <FaMagnifyingGlass size={16} />
        <SearchInput
          ref={inputRef}
          value={query}
          onChange={handleInputChange}
          onKeyDown={handleKeyDown}
          placeholder='Search for resources...'
          autoComplete='off'
          autoCorrect='off'
          autoCapitalize='off'
          spellCheck={false}
        />
        <ShortcutHint onClick={closeSearch}>esc</ShortcutHint>
      </SearchInputWrapper>

      {error ? (
        <ErrorLook style={{ padding: '1rem' }}>{error.message}</ErrorLook>
      ) : (
        <>
          {heading && (
            <HeadingRow
              role={loading ? 'status' : undefined}
              data-testid={loading ? 'search-overlay-loading' : undefined}
            >
              <HeadingIcon>
                {loading ? (
                  <Spinner size='0.9rem' inheritColor />
                ) : (
                  <FaMagnifyingGlass size={12} />
                )}
              </HeadingIcon>
              {heading}
            </HeadingRow>
          )}

          {tags.length > 0 && (
            <Row
              center
              gap='1ch'
              style={{ padding: '0.5rem 1rem', borderBottom: '1px solid' }}
            >
              <TagHeading>With Tags:</TagHeading>
              <span>
                <InlineFormattedResourceList subjects={tags} />
              </span>
            </Row>
          )}

          {showHelperMessage && (
            <HelperMessage>
              Search matches on the names and descriptions of resources.
              Additionally you can filter by tag using <code>tag:[name]</code>
            </HelperMessage>
          )}

          <ResultsArea ref={resultsRef}>
            <Column gap='0.5rem'>
              {loading && results.length === 0 && (
                <>
                  <SkeletonRow aria-hidden />
                  <SkeletonRow aria-hidden />
                  <SkeletonRow aria-hidden />
                </>
              )}
              {results.map((subject, index) => (
                <SelectableResult
                  key={subject}
                  subject={subject}
                  initialInView={index < 5}
                  selected={index === selectedIndex}
                  index={index}
                  onClick={() => {
                    setSelected(index);
                    // Small delay so the user sees the highlight before navigating
                    setTimeout(() => {
                      const openURL = constructOpenURL(subject);
                      navigate(openURL);
                      closeSearch();
                    }, 80);
                  }}
                />
              ))}
            </Column>
          </ResultsArea>

          <FooterRow>
            <FooterHints>
              <span>
                <kbd>↑</kbd> <kbd>↓</kbd> navigate
              </span>
              <span>
                <kbd>↵</kbd> open
              </span>
              <span>
                <kbd>esc</kbd> close
              </span>
            </FooterHints>
            {results.length > 0 && (
              <span>
                {results.length} result{results.length !== 1 ? 's' : ''}
              </span>
            )}
          </FooterRow>
        </>
      )}
    </ErrorBoundary>
  );
}

interface SelectableResultProps {
  subject: string;
  initialInView: boolean;
  selected: boolean;
  index: number;
  onClick: () => void;
}

const SelectableResult: React.FC<SelectableResultProps> = ({
  subject,
  initialInView,
  selected,
  index,
  onClick,
}) => {
  const ref = useRef<HTMLDivElement | null>(null);

  return (
    <div
      ref={ref}
      data-index={index}
      style={{
        borderRadius: '0.375rem',
        background: selected ? 'var(--color-bg1)' : 'transparent',
        cursor: 'pointer',
        transition: 'background 80ms',
      }}
    >
      <ResourceCard
        initialInView={initialInView}
        subject={subject}
        highlight={selected}
        onClick={onClick}
      />
    </div>
  );
};
