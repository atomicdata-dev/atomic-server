import { styled, keyframes, css } from 'styled-components';

const fadeIn = keyframes`
  from {
    opacity: 0;
    top: var(--error-chip-start);
  }
  to {
    opacity: 1;
    top: var(--error-chip-end);
  }
`;

export const ErrorChip = styled.span<{
  noMovement?: boolean;
  top?: string;
}>`
  --error-chip-end: ${p => p.top ?? '0.5rem'};
  --error-chip-start: calc(var(--error-chip-end) - 0.5rem);
  position: relative;
  top: var(--error-chip-end);
  background-color: ${p => p.theme.colors.alert};
  color: white;
  padding: 0.25rem 0.5rem;
  border-radius: ${p => p.theme.radius};
  box-shadow: ${p => p.theme.boxShadowSoft};

  ${p =>
    !p.noMovement
      ? css`
          animation: ${fadeIn} 0.1s ease-in-out;
        `
      : ''}

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

export const ErrorChipInput = styled(ErrorChip)`
  position: absolute;
  --error-chip-end: ${p => p.top ?? '2rem'};
`;
