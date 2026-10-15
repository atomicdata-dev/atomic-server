import type { Resource } from '@tomic/react';
import { FaLock } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { AgentAvatar } from '../../components/Presence/AgentAvatar';
import { useOtherMembers } from './ConversationTitle';

interface ConversationIconProps {
  resource: Resource;
  /** Diameter of one avatar, any CSS size. */
  size?: string;
}

/** Who a conversation is with: the other member's avatar, a facepile of the
 *  first two for a group, or a lock when it is only you. */
export function ConversationIcon({
  resource,
  size = '1.6rem',
}: ConversationIconProps) {
  const others = useOtherMembers(resource);

  if (others.length === 0) {
    return <FaLock />;
  }

  if (others.length === 1) {
    return <AgentAvatar agentSubject={others[0]} size={size} />;
  }

  // Two overlapping avatars take up about the width of one full-size avatar.
  const pileSize = `calc(${size} * 0.65)`;

  return (
    <Facepile $size={pileSize}>
      {others.slice(0, 2).map(member => (
        <AgentAvatar key={member} agentSubject={member} size={pileSize} />
      ))}
    </Facepile>
  );
}

const Facepile = styled.span<{ $size: string }>`
  display: inline-flex;
  align-items: center;
  flex-shrink: 0;
  height: ${p => p.$size};

  & > * + * {
    margin-left: calc(${p => p.$size} * -0.35);
  }
`;
