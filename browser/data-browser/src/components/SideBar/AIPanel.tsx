import { useResource } from '@tomic/react';
import type { JSX } from 'react';
import { FaPlus, FaRegComment } from 'react-icons/fa6';
import { IconButton } from '@components/IconButton/IconButton';
import { useAISidebar } from '@components/AI/AISidebarContext';
import { dataBrowser, useTitle } from '@tomic/react';
import { usePrivateDrive } from '@hooks/usePrivateDrive';
import { useDriveChats } from '@hooks/useDriveChats';
import {
  SideBarMenuRow,
  SideBarMenuRowLabel,
  SideBarMenuRowIcon,
  SideBarMenuItemLink,
} from './SideBarMenuItem';
import { SideBarPanel } from './SideBarPanel';
import { Panel } from './usePanelList';

/** Discover chats throughout the private drive, including legacy duplicate folders. */
export function AIChatsPanel(): JSX.Element | null {
  const { privateDrive } = usePrivateDrive();
  const chats = useDriveChats(privateDrive);

  if (chats.length === 0) return null;

  return (
    <SideBarPanel
      title='AI Chats'
      panel={Panel.AIChats}
      heightStorageKey='aiChatsPanelHeight'
      data-testid='ai-chats-panel'
      actions={<NewSidebarChatButton />}
    >
      {chats.map(subject => (
        <ChatLink key={subject} subject={subject} />
      ))}
    </SideBarPanel>
  );
}

export function NewSidebarChatButton() {
  const { openChat } = useAISidebar();

  return (
    <IconButton
      title='New Chat'
      size='small'
      color='textLight'
      onClick={() => openChat()}
    >
      <FaPlus />
    </IconButton>
  );
}

function ChatLink({ subject }: { subject: string }) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  const emoji = resource.get(dataBrowser.properties.emoji) as
    | string
    | undefined;
  const { openChat } = useAISidebar();

  return (
    <SideBarMenuItemLink
      subject={subject}
      clean
      onClick={event => {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey)
          return;
        event.preventDefault();
        openChat(subject);
      }}
    >
      <SideBarMenuRow>
        <SideBarMenuRowIcon>
          {emoji ? <span aria-hidden>{emoji}</span> : <FaRegComment />}
        </SideBarMenuRowIcon>
        <SideBarMenuRowLabel>{title || 'Untitled Chat'}</SideBarMenuRowLabel>
      </SideBarMenuRow>
    </SideBarMenuItemLink>
  );
}
