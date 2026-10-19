import { useResource } from '@tomic/react';
import { useEffect, useState, type JSX } from 'react';
import { FaPlus } from 'react-icons/fa6';
import { useConversations } from '../../helpers/conversations/useConversations';
import { ConversationIcon } from '../../views/Conversation/ConversationIcon';
import {
  ConversationTitle,
  useMemberNames,
} from '../../views/Conversation/ConversationTitle';
import { NewMessageDialogBody } from '../../views/Conversation/NewMessageDialog';
import { Dialog, useDialog } from '../Dialog';
import { IconButton } from '../IconButton/IconButton';
import {
  SideBarMenuItemLink,
  SideBarMenuRow,
  SideBarMenuRowIcon,
  SideBarMenuRowLabel,
} from './SideBarMenuItem';
import { SideBarPanel } from './SideBarPanel';
import { Empty, useSidebarSearch } from './SidebarSearch';
import { Panel, panelTitle } from './usePanelList';

interface MessagesPanelProps {
  onItemClick: () => void;
}

/** The signed-in agent's encrypted conversations, from any drive. */
export function MessagesPanel({
  onItemClick,
}: MessagesPanelProps): JSX.Element {
  const conversations = useConversations();
  const [dialogProps, show, close, isOpen] = useDialog();
  const { query, button, input } = useSidebarSearch(
    'Search messages',
    'search-messages',
  );
  // Which conversations match the query, reported by their links.
  const [matches, setMatches] = useState<Record<string, boolean>>({});
  const filtering = query.trim() !== '';
  const noMatches =
    filtering && conversations.every(subject => matches[subject] === false);

  return (
    <>
      <SideBarPanel
        title={panelTitle(Panel.Messages)}
        panel={Panel.Messages}
        heightStorageKey='messagesPanelHeight'
        initialHeight={200}
        data-testid='messages-panel'
        actions={
          <>
            {conversations.length > 0 && button}
            <IconButton
              title='New message'
              size='small'
              color='textLight'
              onClick={() => show()}
              data-testid='new-message'
            >
              <FaPlus />
            </IconButton>
          </>
        }
      >
        {conversations.length === 0 ? (
          <Empty>No messages yet</Empty>
        ) : (
          <>
            {input}
            {noMatches && <Empty>No matches</Empty>}
            {conversations.map(subject => (
              <ConversationLink
                key={subject}
                subject={subject}
                query={query}
                onMatch={match =>
                  setMatches(prev =>
                    prev[subject] === match
                      ? prev
                      : { ...prev, [subject]: match },
                  )
                }
                onClick={onItemClick}
              />
            ))}
          </>
        )}
      </SideBarPanel>
      <Dialog {...dialogProps} width='30rem'>
        {isOpen && <NewMessageDialogBody onDone={close} />}
      </Dialog>
    </>
  );
}

/** One conversation as a menu row, titled with who is in it. */
export function ConversationLink({
  subject,
  query = '',
  onMatch,
  onClick,
}: {
  subject: string;
  /** Only conversations with a member whose name contains this show. */
  query?: string;
  onMatch?: (match: boolean) => void;
  onClick?: () => void;
}): JSX.Element | null {
  const resource = useResource(subject);
  const names = useMemberNames(resource);
  const needle = query.trim().toLowerCase();
  const match =
    needle === '' || names.some(name => name.toLowerCase().includes(needle));

  useEffect(() => onMatch?.(match), [match, onMatch]);

  if (!match) return null;

  return (
    <SideBarMenuItemLink
      subject={subject}
      clean
      data-testid='conversation-item'
    >
      <SideBarMenuRow onClick={onClick}>
        <SideBarMenuRowIcon>
          <ConversationIcon resource={resource} size='1.4rem' />
        </SideBarMenuRowIcon>
        <SideBarMenuRowLabel>
          <ConversationTitle resource={resource} />
        </SideBarMenuRowLabel>
      </SideBarMenuRow>
    </SideBarMenuItemLink>
  );
}
