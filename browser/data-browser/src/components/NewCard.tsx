import { FaPlus } from 'react-icons/fa';
import { styled } from 'styled-components';
import { GridCard } from '../views/FolderPage/GridItem/components';

export interface NewCardProps {
  onClick: (e: React.MouseEvent) => void;
}

export function NewCard({ onClick }: NewCardProps) {
  return (
    <Thing as='button' onClick={onClick}>
      <FaPlus />
    </Thing>
  );
}

const Thing = styled(GridCard)`
  background-color: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  cursor: pointer;
  display: grid;
  place-items: center;
  height: 100%;
  width: 100%;
  font-size: 3rem;
  color: ${p => p.theme.colors.textLight};
  transition:
    color 0.1s ease-in-out,
    font-size 0.1s ease-out,
    border-color 0.1s ease-in-out;
  &:hover,
  &:focus {
    color: ${p => p.theme.colors.main};
    font-size: 3.8rem;
    border-color: ${p => p.theme.colors.main};
  }

  :active {
    font-size: 3rem;
  }
`;
