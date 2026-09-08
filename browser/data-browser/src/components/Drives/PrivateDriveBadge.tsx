import { styled } from 'styled-components';
import { FaLock } from 'react-icons/fa6';

import type { JSX } from 'react';

/**
 * Marks the one drive that belongs to the person rather than to the work.
 *
 * Next to the title rather than in place of it: the point is to say what this
 * drive is, at the moment someone is about to treat it like any other. The
 * tooltip carries the reason, because "private" alone invites the reading
 * "a drive I have not shared yet", which is the mistake this exists to prevent.
 */
export function PrivateDriveBadge(): JSX.Element {
  return (
    <Badge title='This is your private drive. It holds your drive list, favourites, notifications and chats, and its address comes from your account — so there is only ever one, and it is not a place for a project.'>
      <FaLock />
      <span>Private</span>
    </Badge>
  );
}

const Badge = styled.span`
  display: inline-flex;
  align-items: center;
  gap: 0.4ch;
  background-color: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: 0.25rem;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.8rem;
  padding-inline: 0.4rem;
  white-space: nowrap;
`;
