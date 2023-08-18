import React, { useCallback } from 'react';
import { FaRegStar, FaStar } from 'react-icons/fa';
import { styled } from 'styled-components';
import { useDriveHistory } from '../../hooks/useDriveHistory';
import { useSavedDrives } from '../../hooks/useSavedDrives';

interface FavoriteButtonProps {
  subject: string;
  className?: string;
}

export function FavoriteButton({ subject, className }: FavoriteButtonProps) {
  const [savedDrives, addSaveDrive, removeSaveDrive] = useSavedDrives();
  const [_, addDriveToHistory, removeFromHistory] = useDriveHistory();

  const isFavorite = savedDrives.includes(subject);
  const Icon = isFavorite ? FaStar : FaRegStar;

  const handleClick = useCallback(() => {
    if (isFavorite) {
      removeSaveDrive(subject);
      addDriveToHistory(subject);
    } else {
      addSaveDrive(subject);
      removeFromHistory(subject);
    }
  }, [
    subject,
    savedDrives,
    removeFromHistory,
    addDriveToHistory,
    addSaveDrive,
    removeSaveDrive,
  ]);

  return (
    <StyledButton
      className={className}
      onClick={handleClick}
      title={isFavorite ? 'Remove from favorites' : 'Add to favorites'}
    >
      <Icon />
    </StyledButton>
  );
}

const StyledButton = styled.button`
  background: none;
  border: none;
  cursor: pointer;
  color: ${p => p.theme.colors.main};
  width: 1.3rem;
  display: flex;
  align-items: center;
  padding: 0;
`;
