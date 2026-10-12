import type { IconType } from 'react-icons';
import type { JSX } from 'react';
import { styled } from 'styled-components';

interface PanelHeaderProps {
  icon: IconType;
  label: string;
}

/** Names the block being edited, so the settings panel reads correctly the
 * moment you select something — before you've looked at anything else in it.
 * Shared between the field and page settings panels. */
export function PanelHeader({
  icon: Icon,
  label,
}: PanelHeaderProps): JSX.Element {
  return (
    <PanelHeaderStyled>
      <Icon />
      {label}
    </PanelHeaderStyled>
  );
}

const PanelHeaderStyled = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: bold;
  color: ${p => p.theme.colors.text};

  svg {
    flex-shrink: 0;
    color: ${p => p.theme.colors.main};
  }
`;
