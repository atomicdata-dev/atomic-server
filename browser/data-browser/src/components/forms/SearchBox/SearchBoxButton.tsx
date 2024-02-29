import { styled } from 'styled-components';

export const SearchBoxButton = styled.button<{ ephimeral?: boolean }>`
  background-color: transparent;
  border: none;
  border-left: ${p =>
    p.ephimeral ? 'none' : '1px solid ' + p.theme.colors.bg2};
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

  visibility: ${p => (p.ephimeral ? 'hidden' : 'visible')};
  div:hover > & {
    visibility: visible;
  }
`;
