import { styled } from 'styled-components';
import { useResource, useTitle, dataBrowser } from '@tomic/react';
import { AIIcon } from '../../components/AI/AIIcon';
import { ConversationIcon } from '../../views/Conversation/ConversationIcon';
import { ConversationTitle } from '../../views/Conversation/ConversationTitle';
import type { ChatMatch } from './chatMatches';

/** A DM or AI chat found by the search overlay, with its avatar or AI icon
 *  and a label saying what kind of result it is. */
export function ChatMatchRow({
  match,
  index,
  selected,
  onClick,
}: {
  match: ChatMatch;
  index: number;
  selected: boolean;
  onClick: () => void;
}) {
  const resource = useResource(match.subject);
  const [title] = useTitle(resource);
  const emoji = resource.get(dataBrowser.properties.emoji) as
    | string
    | undefined;
  const isDm = match.kind === 'dm';

  return (
    <Row
      type='button'
      data-index={index}
      data-testid='search-chat-match'
      onClick={onClick}
      $selected={selected}
    >
      <IconSlot>
        {isDm ? (
          <ConversationIcon resource={resource} size='1.6rem' />
        ) : emoji ? (
          <span aria-hidden>{emoji}</span>
        ) : (
          <AIIcon />
        )}
      </IconSlot>
      <Name>
        {isDm ? (
          <ConversationTitle resource={resource} />
        ) : (
          title || 'Untitled Chat'
        )}
      </Name>
      <Kind>{isDm ? 'Message' : 'AI chat'}</Kind>
    </Row>
  );
}

const Row = styled.button<{ $selected: boolean }>`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
  padding: 0.65rem 1rem;
  border: none;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  background: ${p => (p.$selected ? p.theme.colors.bg1 : 'transparent')};
  color: ${p => p.theme.colors.text};
  font-size: 0.875rem;
  text-align: left;
  cursor: pointer;
  transition: background 80ms;

  &:hover {
    background: ${p => p.theme.colors.bg1};
  }
`;

const IconSlot = styled.span`
  display: flex;
  align-items: center;
  justify-content: center;
  width: 1.6rem;
  flex-shrink: 0;
`;

const Name = styled.span`
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const Kind = styled.span`
  flex-shrink: 0;
  padding: 0.1rem 0.5rem;
  border-radius: 1rem;
  background: ${p => p.theme.colors.bg1};
  color: ${p => p.theme.colors.textLight};
  font-size: 0.75rem;
`;
