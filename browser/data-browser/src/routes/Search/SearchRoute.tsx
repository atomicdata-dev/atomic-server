import { useEffect, useRef, useState, type JSX } from 'react';
import { ContainerNarrow } from '../../components/Containers';
import { useHotkeys } from 'react-hotkeys-hook';
import { constructOpenURL } from '../../helpers/navigation';
import ResourceCard from '../../views/Card/ResourceCard';
import { dataBrowser, useServerSearch } from '@tomic/react';
import { ErrorLook } from '../../components/ErrorLook';
import { styled } from 'styled-components';
import { FaMagnifyingGlass } from 'react-icons/fa6';
import { useQueryScopeHandler } from '../../hooks/useQueryScope';
import { useSettings } from '../../helpers/AppSettings';
import { Column, Row } from '../../components/Row';
import { Main } from '../../components/Main';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { createRoute, useSearch } from '@tanstack/react-router';
import { pathNames } from '../paths';
import { appRoute } from '../RootRoutes';
import { base64StringToFilter } from './searchUtils';
import { InlineFormattedResourceList } from '../../components/InlineFormattedResourceList';
import { ErrorBoundary } from '../../views/ErrorPage';
import { useOnValueChange } from '@helpers/useOnValueChange';

type SearchRouteQueryParams = {
  query?: string;
  queryscope?: string;
  /** Base64 encoded filter object */
  filters?: string;
};

export const SearchRoute = createRoute({
  path: pathNames.search,
  component: () => null,
  getParentRoute: () => appRoute,
  validateSearch: {
    parse: (search: Record<string, unknown>): SearchRouteQueryParams => {
      return {
        query: (search.query as string) ?? undefined,
        queryscope: (search.queryscope as string) ?? undefined,
        filters: (search.filters as string) ?? undefined,
      };
    },
  },
});

/** Full text search route */
export function Search(): JSX.Element {
  const { query, filters: filtersBase64 } = useSearch({
    strict: false,
    select: state => ({ query: state.query, filters: state.filters }),
  });
  const { drive } = useSettings();
  const { scope } = useQueryScopeHandler();

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

  const navigate = useNavigateWithTransition();

  const resultsDiv = useRef<HTMLDivElement | null>(null);

  useHotkeys(
    'enter',
    e => {
      e.preventDefault();
      // Get the current subject from the latest results and selectedIndex
      const selectedSubject = results[selectedIndex];

      if (selectedSubject) {
        //@ts-expect-error blur does exist though
        document?.activeElement?.blur();
        const openURL = constructOpenURL(selectedSubject);
        navigate(openURL);
      }
    },
    { enableOnFormTags: ['INPUT'], enableOnContentEditable: true },
    // Explicitly include results and selectedIndex in the dependency array
    [results, selectedIndex, navigate],
  );

  useHotkeys(
    'up',
    e => {
      e.preventDefault();
      setSelected(prev => (prev > 0 ? prev - 1 : 0));
    },
    { enableOnFormTags: ['INPUT'], enableOnContentEditable: true },
    [selectedIndex],
  );

  useHotkeys(
    'down',
    e => {
      e.preventDefault();
      setSelected(prev =>
        prev === results.length - 1 ? results.length - 1 : prev + 1,
      );
    },
    { enableOnFormTags: ['INPUT'], enableOnContentEditable: true },
    [selectedIndex],
  );

  let heading: string | undefined = 'No hits';

  if (!query) {
    heading = 'Enter a search query';
  }

  if (loading) {
    heading = 'Loading results...';
  }

  const showHelperMessage = !query && filterIsEmpty;

  useOnValueChange(() => {
    setSelected(0);
  }, [query]);

  return (
    <Main>
      <ContainerNarrow>
        {error ? (
          <ErrorLook>{error.message}</ErrorLook>
        ) : (
          <>
            <Column gap='1rem'>
              <Heading>
                <FaMagnifyingGlass />
                <span>
                  {heading ? (
                    heading
                  ) : loading ? (
                    <>
                      Searching for <QueryText>{query}</QueryText>...
                    </>
                  ) : (
                    <>
                      {results.length}{' '}
                      {results.length > 1 ? 'Results' : 'Result'} for{' '}
                      <QueryText>{query}</QueryText>
                    </>
                  )}
                </span>
              </Heading>
              {tags.length > 0 && (
                <Row center gap='1ch'>
                  <TagHeading>With Tags:</TagHeading>
                  <span>
                    <InlineFormattedResourceList subjects={tags} />
                  </span>
                </Row>
              )}
              {showHelperMessage && (
                <HelperMessage>
                  Search matches on the names and descriptions of resources.
                  Additionally you can search for resources with specific tags
                  by adding <code>tag:[name]</code> to your search.
                </HelperMessage>
              )}
              <ErrorBoundary>
                <Column
                  ref={resultsDiv}
                  gap='1rem'
                  // style={{ opacity: loading ? 0.5 : 1, transition: 'opacity .2s' }}
                >
                  {results.map((subject, index) => (
                    <SelectableResult
                      key={subject}
                      subject={subject}
                      initialInView={index < 5}
                      selected={index === selectedIndex}
                    />
                  ))}
                </Column>
              </ErrorBoundary>
            </Column>
          </>
        )}
      </ContainerNarrow>
    </Main>
  );
}

interface SelectableResultProps {
  subject: string;
  initialInView: boolean;
  selected: boolean;
}

const SelectableResult: React.FC<SelectableResultProps> = ({
  subject,
  initialInView,
  selected,
}) => {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (ref.current && selected) {
      ref.current.scrollIntoView({ block: 'nearest', behavior: 'instant' });
    }
  }, [selected]);

  return (
    <div ref={ref}>
      <ResourceCard
        initialInView={initialInView}
        subject={subject}
        key={subject}
        highlight={selected}
      />
    </div>
  );
};

const Heading = styled.h1`
  color: ${p => p.theme.colors.text};
  display: flex;
  align-items: center;
  gap: 0.7ch;
  white-space: nowrap;
  overflow: hidden;
  line-height: 1.5;

  & > span {
    overflow: hidden;
    text-overflow: ellipsis;
  }
`;

const QueryText = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const TagHeading = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-weight: bold;
`;

const HelperMessage = styled.p`
  color: ${p => p.theme.colors.textLight};
  border: 1px solid ${p => p.theme.colors.bg2};
  padding: 1rem;
  border-radius: 0.5rem;
`;
