import { styled } from 'styled-components';
import { SB_BOTTOM_RADIUS, SB_HIGHLIGHT, SB_TOP_RADIUS } from './searchboxVars';

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
  visibility: ${p => (p.ephimeral ? 'hidden' : 'visible')};

  &:last-child {
    border-top-right-radius: ${p => SB_TOP_RADIUS.var(p.theme.radius)};
    border-bottom-right-radius: ${p => SB_BOTTOM_RADIUS.var(p.theme.radius)};
  }

  &:disabled {
    color: ${p => p.theme.colors.textLight2};
    cursor: not-allowed;
  }

  &:not(:disabled) {
    &:hover,
    &:focus-visible {
      color: ${SB_HIGHLIGHT.var()};
      background-color: ${p => p.theme.colors.bg1};
      border-color: ${SB_HIGHLIGHT.var()};
    }
  }

  div:hover > & {
    visibility: visible;
  }
`;
