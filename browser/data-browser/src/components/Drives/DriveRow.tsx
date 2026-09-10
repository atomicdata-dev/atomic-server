import { styled } from 'styled-components';

import { FaRegCircle, FaSquareCheck, FaXmark } from 'react-icons/fa6';
import { ResourceInline } from '../../views/ResourceInline';
import { FavoriteButton } from './FavoriteButton';
import { IconButton } from '../../components/IconButton/IconButton';
import { PrivateDriveBadge } from './PrivateDriveBadge';

export interface DriveRowProps {
  subject: string;
  label?: string;
  /** This is the drive the app is currently on. */
  selected?: boolean;
  /** The private drive can't be starred or unstarred — it's always yours. */
  hideFavorite?: boolean;
  /**
   * Marks this row as the private drive.
   *
   * It sits in the same list as everything else, so the badge is what keeps it
   * from reading as an ordinary drive that happens to be first.
   */
  isPrivate?: boolean;
  onClick: (subject: string) => void;
  onRemove?: (subject: string) => void;
}

/**
 * One drive, in a list where exactly one of them is the one you are on.
 *
 * The row IS the control: the radio, the name and the badge are a single
 * target spanning the full width, and the hover state covers the same ground.
 * Anything less means aiming at part of a line in order to choose the thing
 * the whole line names.
 *
 * No subject and no connection light. The DID took three quarters of the row's
 * width in order to be truncated, and is neither read nor typed. The light
 * showed a websocket's ready state, which for a drive you are not on says
 * nothing about that drive — no socket is open to it — while a transient
 * CLOSING rendered as an orange warning about nothing at all.
 */
export function DriveRow({
  subject,
  label,
  selected,
  hideFavorite,
  isPrivate,
  onClick,
  onRemove,
}: DriveRowProps) {
  return (
    <Wrapper>
      <Choice
        type='button'
        role='radio'
        aria-checked={!!selected}
        $selected={!!selected}
        onClick={() => onClick(subject)}
      >
        {selected ? <FaSquareCheck /> : <FaRegCircle />}
        <Name>{label || <ResourceInline subject={subject} />}</Name>
        {isPrivate && <PrivateDriveBadge />}
      </Choice>
      <Actions>
        {!hideFavorite && <FavoriteButton subject={subject} />}
        {onRemove && (
          <IconButton
            title='Remove drive from list'
            onClick={() => onRemove(subject)}
          >
            <FaXmark />
          </IconButton>
        )}
      </Actions>
    </Wrapper>
  );
}

const Wrapper = styled.div`
  display: flex;
  align-items: center;
  /* Padding only on the right: the choice pays its own leading space, so its
     hover state starts at the card's edge rather than inside a gutter. */
  padding-right: 0.5rem;

  &:hover {
    background-color: ${p => p.theme.colors.bg1};
  }
`;

const Choice = styled.button<{ $selected: boolean }>`
  flex: 1;
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 0.6rem;
  background: none;
  border: none;
  padding: 0.5rem 0.75rem;
  cursor: pointer;
  color: inherit;
  font-size: inherit;
  text-align: left;

  svg {
    flex-shrink: 0;
    color: ${p =>
      p.$selected ? p.theme.colors.main : p.theme.colors.textLight};
  }

  &:focus-visible {
    outline: 2px solid ${p => p.theme.colors.main};
    outline-offset: -2px;
  }
`;

const Name = styled.span`
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
`;

const Actions = styled.div`
  display: flex;
  align-items: center;
  gap: 0.25rem;
  flex-shrink: 0;
`;
