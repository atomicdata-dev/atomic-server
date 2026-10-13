import { useResource } from '@tomic/react';
import type { JSX } from 'react';
import { FaLock, FaPlus } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { useConversations } from '../../helpers/conversations/useConversations';
import { ConversationTitle } from '../../views/Conversation/ConversationTitle';
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
import { Panel } from './usePanelList';

interface MessagesPanelProps {
  onItemClick: () => void;
}

/** The signed-in agent's encrypted conversations, from any drive. */
export function MessagesPanel({
  onItemClick,
}: MessagesPanelProps): JSX.Element {
  const conversations = useConversations();
  const [dialogProps, show, close, isOpen] = useDialog();

  return (
    <>
      <SideBarPanel
        title='Messages'
        panel={Panel.Messages}
        heightStorageKey='messagesPanelHeight'
        initialHeight={200}
        data-testid='messages-panel'
        actions={
          <IconButton
            title='New message'
            size='small'
            color='textLight'
            onClick={() => show()}
            data-testid='new-message'
          >
            <FaPlus />
          </IconButton>
        }
      >
        {conversations.length === 0 ? (
          <Empty>No messages yet</Empty>
        ) : (
          conversations.map(subject => (
            <ConversationLink
              key={subject}
              subject={subject}
              onClick={onItemClick}
            />
          ))
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
  onClick,
}: {
  subject: string;
  onClick: () => void;
}): JSX.Element {
  const resource = useResource(subject);

  return (
    <SideBarMenuItemLink
      subject={subject}
      clean
      data-testid='conversation-item'
    >
      <SideBarMenuRow onClick={onClick}>
        <SideBarMenuRowIcon>
          <FaLock />
        </SideBarMenuRowIcon>
        <SideBarMenuRowLabel>
          <ConversationTitle resource={resource} />
        </SideBarMenuRowLabel>
      </SideBarMenuRow>
    </SideBarMenuItemLink>
  );
}

const Empty = styled.p`
  margin: 0;
  padding: 0.25rem 0.5rem;
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;
