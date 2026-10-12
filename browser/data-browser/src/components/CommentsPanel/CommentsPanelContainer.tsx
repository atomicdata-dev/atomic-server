import { useEffect } from 'react';
import { dataBrowser, useResource, useStore, useTitle } from '@tomic/react';
import { styled } from 'styled-components';
import { RightPanel } from '../RightPanel/RightPanel';
import { useRightPanel } from '../RightPanel/RightPanelContext';
import { useContextualPanel } from '../RightPanel/useContextualPanel';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';
import { useLastSeenComments } from '../../hooks/useLastSeenComments';
import { getResourcesDrive } from '../../helpers/getResourcesDrive';
import { getOrCreateCommentsFolder } from '../../helpers/standardLocations';
import { ChatView, useChatMessages } from '../../views/ChatRoom/ChatRoomView';
import { Column } from '../Row';

/**
 * Right-side panel showing the comments on the current resource. Comments are
 * entries in ChatLog pages whose `about` points at the resource (older ones are
 * Message resources) — there is no chatroom container, so the thread needs no
 * setup step and the first comment is just a regular client-signed commit.
 */
export const CommentsPanelContainer: React.FC = () => {
  const [pageSubject] = useCurrentSubject();
  const { commentSubject, clearCommentTarget } = useRightPanel();
  // The panel's scope outlives a navigation (it is keyed by agent + drive), so
  // a thread opened for something on *this* page — a table row — must not
  // follow the user to the next one.
  useEffect(() => {
    clearCommentTarget();
  }, [pageSubject, clearCommentTarget]);
  const subject = commentSubject ?? pageSubject;
  const isOpen = useContextualPanel('comments', subject);

  return (
    <RightPanel isOpen={isOpen} testId='comments-panel'>
      {isOpen && subject && (
        <CommentsPanel subject={subject} isRowThread={!!commentSubject} />
      )}
      {isOpen && !subject && (
        <EmptyState>Open a resource to see its comments.</EmptyState>
      )}
    </RightPanel>
  );
};

function CommentsPanel({
  subject,
  isRowThread,
}: {
  subject: string;
  isRowThread: boolean;
}) {
  return (
    <PanelWrapper>
      <PanelTitle>Comments</PanelTitle>
      {/* Which row you are commenting on isn't visible from the panel
       * otherwise — the page behind it still shows the whole table. */}
      {isRowThread && <ThreadSubtitle subject={subject} />}
      <Comments subject={subject} />
    </PanelWrapper>
  );
}

function ThreadSubtitle({ subject }: { subject: string }) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);

  return <Subtitle data-testid='comments-panel-subtitle'>{title}</Subtitle>;
}

function Comments({ subject }: { subject: string }) {
  const store = useStore();
  const resource = useResource(subject);
  const { messages, loading, olderCount, loadOlder, send } = useChatMessages(
    subject,
    dataBrowser.properties.about,
  );
  const [, markSeen] = useLastSeenComments(subject);

  // Everything in the thread is visible while the panel is open — mark the
  // rendered messages as seen.
  const seenCount = messages.length + olderCount;
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
    await send(text, { parent: commentsFolder, replyTo });
  };

  return (
    <ChatView
      messages={messages}
      loading={loading}
      olderCount={olderCount}
      onLoadOlder={loadOlder}
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

const Subtitle = styled.p`
  margin: 0;
  padding-bottom: ${p => p.theme.size(2)};
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
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
