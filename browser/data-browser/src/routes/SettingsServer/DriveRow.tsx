import { styled } from 'styled-components';

import { Button } from '../../components/Button';
import { WSIndicator } from './WSIndicator';
import { ResourceInline } from '../../views/ResourceInline';
import { FavoriteButton } from './FavoriteButton';

export interface DriveRowProps {
  subject: string;
  onClick: (subject: string) => void;
  disabled?: boolean;
}

export function DriveRow({ subject, onClick, disabled }: DriveRowProps) {
  return (
    <DriveRowWrapper>
      <TitleWrapper>
        <ResourceInline subject={subject} />
      </TitleWrapper>
      <Subject>{subject}</Subject>
      <SelectButton onClick={() => onClick(subject)} disabled={disabled}>
        Select
      </SelectButton>
      <StyledFavoriteButton subject={subject} />
      <StyledWSIndicator subject={subject} />
    </DriveRowWrapper>
  );
}

const DriveRowWrapper = styled.div`
  --title-font-weight: 500;
  display: grid;
  grid-template-areas: 'title ws subject button icon';
  grid-template-columns: 20ch 1.3rem auto 10ch 1.3rem;
  gap: ${p => p.theme.margin}rem;
  align-items: center;
  padding-block: 0.3rem;

  @container (max-width: 500px) {
    grid-template-areas: 'ws title icon' 'subject subject subject' 'button button button';
    grid-template-columns: 1.3rem auto 1rem;
    padding-block: 1rem;
    --title-font-weight: bold;
  }
`;

const StyledFavoriteButton = styled(FavoriteButton)`
  grid-area: icon;
`;

const Subject = styled.span`
  grid-area: subject;
  color: ${p => p.theme.colors.textLight};
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
`;

const SelectButton = styled(Button)`
  grid-area: button;
  background-color: ${p => (p.disabled ? p.theme.colors.main : 'transparent')};
  color: ${p => (p.disabled ? 'white' : p.theme.colors.main)};
  align-self: flex-end;
`;

const StyledWSIndicator = styled(WSIndicator)`
  grid-area: ws;
`;

const TitleWrapper = styled.div`
  grid-area: title;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  font-weight: var(--title-font-weight);
`;
