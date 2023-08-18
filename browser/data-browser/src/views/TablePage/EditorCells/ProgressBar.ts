import { styled } from 'styled-components';

interface ProgressBarProps {
  percentage: number;
}

export const ProgressBar = styled.span<ProgressBarProps>`
  --off: transparent;
  --on: ${({ theme }) => theme.colors.main};
  position: absolute;
  background-image: ${props =>
    `linear-gradient(to right, var(--on), var(--on) ${props.percentage}%, var(--off) ${props.percentage}%)`};
  height: 4px;
  width: 100%;
  left: 0;
  bottom: 0px;
`;
