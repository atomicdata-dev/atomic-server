import {
  ai,
  commits,
  core,
  unknownSubject,
  useCollection,
  useResource,
} from '@tomic/react';
import { useEffect, useState, type JSX } from 'react';
import { FaPlus, FaRegComment } from 'react-icons/fa6';
import { IconButton } from '@components/IconButton/IconButton';
import { useAISidebar } from '@components/AI/AISidebarContext';
import { dataBrowser, useTitle } from '@tomic/react';
import { usePrivateDrive } from '@hooks/usePrivateDrive';
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

/** Live class query, independent of the drive's storage-folder pointer. */
function useDriveChats(drive: string | undefined): string[] {
  const [subjects, setSubjects] = useState<string[]>([]);

  const { collection, ready } = useCollection(
    {
      property: core.properties.isA,
      value: ai.classes.aiChat,
      filters: [
        {
          property: 'https://atomicdata.dev/properties/drive',
          value: drive ?? unknownSubject,
        },
      ],
      drive: drive ?? unknownSubject,
      sort_by: commits.properties.createdAt,
      sort_desc: true,
    },
    { pageSize: 100 },
  );

  useEffect(() => {
    if (!ready || !drive) {
      setSubjects([]);

      return;
    }

    let cancelled = false;

    const extract = async () => {
      const members: string[] = [];

      for (let i = 0; i < collection.totalMembers; i++) {
        const member = await collection.getMemberWithIndex(i);

        if (member) {
          members.push(member);
        }
      }

      if (!cancelled) {
        setSubjects(members);
      }
    };

    extract();

    return () => {
      cancelled = true;
    };
  }, [collection, ready, drive]);

  return subjects;
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
