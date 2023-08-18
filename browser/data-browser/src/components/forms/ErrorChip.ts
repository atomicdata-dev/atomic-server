import { styled, keyframes } from 'styled-components';

const fadeIn = keyframes`
  from {
    opacity: 0;
    top: var(--error-chip-starting-position);
  }
  to {
    opacity: 1;
    top: 0.5rem;
  }
`;

export const ErrorChip = styled.span<{ noMovement?: boolean }>`
  --error-chip-starting-position: ${p => (p.noMovement ? '0.5rem' : '0rem')};
  position: relative;
  top: 0.5rem;
  background-color: ${p => p.theme.colors.alert};
  color: white;
  padding: 0.25rem 0.5rem;
  border-radius: ${p => p.theme.radius};
  animation: ${fadeIn} 0.1s ease-in-out;
  box-shadow: ${p => p.theme.boxShadowSoft};

  &::before {
    --triangle-size: 0.5rem;
    content: '';
    position: absolute;
    top: calc(-1 * var(--triangle-size) + 1px);
    left: 1rem;
    width: var(--triangle-size);
    aspect-ratio: 1/1;
    background-color: ${p => p.theme.colors.alert};
    clip-path: polygon(0% 100%, 100% 100%, 50% 0%);
  }
`;
