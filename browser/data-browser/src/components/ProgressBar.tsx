import { styled } from 'styled-components';

interface ProgressBarProps {
  value: number;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({ value }) => {
  return <Progress value={value} max='100' />;
};

const Progress = styled.progress`
  --progress-bg: ${p => p.theme.colors.bg1};
  --progress-fg: ${p => p.theme.colors.main};
  --progress-radius: 2rem;
  --progress-height: 0.5rem;

  flex: 1;
  appearance: none;
  // Needed for the border radius to work on chrome
  overflow: hidden;

  // Firefox
  border-radius: var(--progress-radius);
  height: var(--progress-height);
  background-color: var(--progress-bg);
  border: none;

  &[value]::-moz-progress-bar {
    background-color: var(--progress-fg);
  }

  // Chrome & Safari
  &[value]::-webkit-progress-bar {
    background-color: var(--progress-bg);
    border-radius: var(--progress-radius);
    height: var(--progress-height);
  }

  &[value]::-webkit-progress-value {
    background-color: var(--progress-fg);
  }
`;
