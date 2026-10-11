import { useResource } from '@tomic/react';
import { useEffect, useState, type JSX } from 'react';
import { FaMagnifyingGlass, FaPlus } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { useDmTextMatches } from '../../routes/Search/useChatMatches';
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
  const [searching, setSearching] = useState(false);
  const [query, setQuery] = useState('');
  // Which conversations match the query, reported by their links.
  const [matches, setMatches] = useState<Record<string, boolean>>({});
  const foundByText = useDmTextMatches(query, searching);
  const filtering = searching && query.trim() !== '';
  const noMatches =
    filtering && conversations.every(subject => matches[subject] === false);

  const closeSearch = () => {
    setSearching(false);
    setQuery('');
  };

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
            {conversations.length > 0 && (
              <IconButton
                title='Search messages'
                size='small'
                color='textLight'
                onClick={() => (searching ? closeSearch() : setSearching(true))}
                data-testid='search-messages'
              >
                <FaMagnifyingGlass />
              </IconButton>
            )}
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
            {searching && (
              <SearchInput
                autoFocus
                type='search'
                aria-label='Search messages'
                placeholder='Search by name'
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Escape') closeSearch();
                }}
                data-testid='search-messages-input'
              />
            )}
            {noMatches && <Empty>No matches</Empty>}
            {conversations.map(subject => (
              <ConversationLink
                key={subject}
                subject={subject}
                query={searching ? query : ''}
                textMatch={foundByText.has(subject)}
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

function ConversationLink({
  subject,
  query,
  textMatch,
  onMatch,
  onClick,
}: {
  subject: string;
  /** Only conversations with a member whose name contains this show. */
  query: string;
  /** The local index found the query in a message of this conversation. */
  textMatch: boolean;
  onMatch: (match: boolean) => void;
  onClick: () => void;
}): JSX.Element | null {
  const resource = useResource(subject);
  const names = useMemberNames(resource);
  const needle = query.trim().toLowerCase();
  const match =
    needle === '' ||
    textMatch ||
    names.some(name => name.toLowerCase().includes(needle));

  useEffect(() => onMatch(match), [match, onMatch]);

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

const SearchInput = styled.input`
  box-sizing: border-box;
  width: calc(100% - 1rem);
  margin: 0.25rem 0.5rem;
  padding: 0.3rem 0.5rem;
  font: inherit;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.text};
  background: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};

  &:focus-visible {
    outline: 2px solid ${p => p.theme.colors.main};
  }
`;

const Empty = styled.p`
  margin: 0;
  padding: 0.25rem 0.5rem;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;
