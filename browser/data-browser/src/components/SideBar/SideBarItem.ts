import { styled } from 'styled-components';

export interface SideBarItemProps {
  disabled?: boolean;
  current?: boolean;
}

/** SideBarItem should probably be wrapped in an AtomicLink for optimal behavior */
export const SideBarItem = styled('span')<SideBarItemProps>`
  box-sizing: border-box;
  display: flex;
  min-height: ${props => props.theme.margin * 0.5 + 1}rem;
  align-items: center;
  justify-content: flex-start;
  color: ${p => (p.disabled ? p.theme.colors.main : p.theme.colors.textLight)};
  padding: 0.2rem;
  text-overflow: ellipsis;
  text-decoration: none;
  border-radius: ${p => p.theme.radius};
  overflow: hidden;
  &:focus-visible {
    background-color: ${p => p.theme.colors.bg1};
  }
  /* Touch devices keep :hover after a tap, so only apply it with a real hover. */
  @media (hover: hover) {
    &:hover {
      background-color: ${p => p.theme.colors.bg1};
    }
  }
  &:active {
    background-color: ${p => p.theme.colors.bg2};
  }

  ${props =>
    props.current &&
    `
    color: ${props.theme.colors.main};
  `}

  svg {
    font-size: 0.8rem;
  }
`;
