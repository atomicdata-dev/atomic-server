import { styled } from 'styled-components';
import { AtomicLink } from '../../AtomicLink';

export const StyledLink = styled(AtomicLink)`
  flex: 1;
  overflow: hidden;
  white-space: nowrap;
`;
export const TextWrapper = styled.span`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
`;
