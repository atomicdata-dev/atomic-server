import { useEffect } from 'react';
import { dataBrowser, useResource, useStore } from '@tomic/react';
import { styled } from 'styled-components';
import { RightPanel } from '../RightPanel/RightPanel';
import { useContextualPanel } from '../RightPanel/useContextualPanel';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { useLastSeenComments } from '../../hooks/useLastSeenComments';
import { getResourcesDrive } from '../../helpers/getResourcesDrive';
import { getOrCreateCommentsFolder } from '../../helpers/standardLocations';
import {
  ChatView,
  sendChatMessage,
  useChatMessages,
} from '../../views/ChatRoom/ChatRoomView';
import { Column } from '../Row';

/**
 * Right-side panel showing the comments on the current resource. Comments are
 * plain Message resources whose `about` points at the resource — there is no
 * chatroom container, so the thread needs no setup step and the first comment
 * is just a regular client-signed commit.
 */
export const CommentsPanelContainer: React.FC = () => {
  const [subject] = useCurrentSubject();
  const isOpen = useContextualPanel('comments', subject);

  return (
    <RightPanel isOpen={isOpen} testId='comments-panel'>
      {isOpen && <CommentsPanel />}
    </RightPanel>
  );
};

function CommentsPanel() {
  const [subject] = useCurrentSubject();

  if (!subject) {
    return <EmptyState>Open a resource to see its comments.</EmptyState>;
  }

  return (
    <PanelWrapper>
      <PanelTitle>Comments</PanelTitle>
      <Comments subject={subject} />
    </PanelWrapper>
  );
}

function Comments({ subject }: { subject: string }) {
  const store = useStore();
  const resource = useResource(subject);
  const { messages, loading, invalidate } = useChatMessages(
    subject,
    dataBrowser.properties.about,
  );
  const [, markSeen] = useLastSeenComments(subject);

  // Everything in the thread is visible while the panel is open — mark the
  // rendered messages as seen.
  const seenCount = messages.length;
  useEffect(() => {
    if (seenCount > 0) {
      markSeen(seenCount);
    }
  }, [seenCount, markSeen]);

  const handleSend = async (text: string, replyTo?: string) => {
    // Comments live in the drive's Comments folder (a standard location) so
    // their read rights can differ from the commented resource itself.
    const drive = await getResourcesDrive(resource, store);
    const commentsFolder = await getOrCreateCommentsFolder(store, drive);
    await sendChatMessage(store, {
      parent: commentsFolder,
      about: subject,
      text,
      replyTo,
    });
    invalidate();
  };

  return (
    <ChatView
      messages={messages}
      loading={loading}
      onSend={handleSend}
      noContainerPadding
      threadSubject={subject}
    />
  );
}

const PanelWrapper = styled(Column)`
  height: 100%;
`;

const PanelTitle = styled.h2`
  font-size: 1rem;
  margin: 0;
  padding-block: ${p => p.theme.size(2)};
`;

const EmptyState = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  height: 100%;
  color: ${p => p.theme.colors.textLight};
`;
