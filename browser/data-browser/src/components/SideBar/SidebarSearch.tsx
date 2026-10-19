import { useState, type JSX } from 'react';
import { FaMagnifyingGlass } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { IconButton } from '../IconButton/IconButton';

/**
 * Toggleable name search for a sidebar panel. Render `button` in the panel
 * actions and `input` at the top of its body; filter on `query`, which is ''
 * while the box is closed. The box closes (and clears) on Escape and blur.
 */
export function useSidebarSearch(
  label: string,
  testId: string,
): { query: string; button: JSX.Element; input: JSX.Element | null } {
  const [searching, setSearching] = useState(false);
  const [query, setQuery] = useState('');

  const close = () => {
    setSearching(false);
    setQuery('');
  };

  return {
    query,
    button: (
      <IconButton
        title={label}
        size='small'
        color='textLight'
        // Keep focus in the input so the click toggles instead of blur-closing and reopening.
        onMouseDown={e => e.preventDefault()}
        onClick={() => (searching ? close() : setSearching(true))}
        data-testid={testId}
      >
        <FaMagnifyingGlass />
      </IconButton>
    ),
    input: searching ? (
      <SearchInput
        autoFocus
        type='search'
        aria-label={label}
        placeholder='Search by name'
        value={query}
        onChange={e => setQuery(e.target.value)}
        onBlur={close}
        onKeyDown={e => {
          if (e.key === 'Escape') close();
        }}
        data-testid={`${testId}-input`}
      />
    ) : null,
  };
}

const SearchInput = styled.input`
  box-sizing: border-box;
  width: calc(100% - 1rem);
  margin: 0.25rem 0.5rem;
  padding: 0.3rem 0.5rem;
  font: inherit;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.text};
  background: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};

  &:focus-visible {
    outline: 2px solid ${p => p.theme.colors.main};
  }
`;

export const Empty = styled.p`
  margin: 0;
  padding: 0.25rem 0.5rem;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;
