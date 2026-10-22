import { useEffect, useRef, useState } from 'react';
import { dataBrowser, unknownSubject, useResource } from '@tomic/react';
import { styled } from 'styled-components';
import { FaXmark } from 'react-icons/fa6';
import { useRightPanel } from '../components/RightPanel/RightPanelContext';
import { useContextualPanel } from '../components/RightPanel/useContextualPanel';
import { useFollow } from '../components/Presence/FollowContext';
import { ChatRoomView } from '../views/ChatRoom/ChatRoomView';
import { EditableTitle } from '../components/EditableTitle';
import { IconButton } from '../components/IconButton/IconButton';
import { registerOverlay } from './overlayBack';
import { openNative } from './hostActions';

/**
 * The meeting's chat in the embed, over the whole page. The web app shows it in
 * the follow-session side panel, which also holds the live call and the
 * presence list; neither works in the app's web view (no connection to a
 * server, no microphone or camera), so only the chat is shown. Closed with the
 * button or the host's Back.
 *
 * The app has a native chat screen of its own: it is asked to open that first
 * (`openNative`), and this overlay is the fallback for when it does not.
 */
export function MeetingChatOverlay(): React.JSX.Element | null {
  const { selectedMeeting, closePanel } = useRightPanel();
  const { followedSession, activeMeeting } = useFollow();
  const subject = selectedMeeting ?? followedSession ?? activeMeeting;
  const isOpen = useContextualPanel('followSession', subject);
  const resource = useResource(subject ?? unknownSubject);
  const title = resource.title;
  // The meeting the app declined to show natively: the overlay is for that.
  const [declined, setDeclined] = useState<string>();
  // Kept out of the effect's dependencies: a changing identity of either must
  // not ask the app a second time (a second screen).
  const latest = useRef({ closePanel, title });

  latest.current = { closePanel, title };

  useEffect(() => {
    if (!isOpen || !subject || declined === subject) return;
    let cancelled = false;

    void openNative(
      dataBrowser.classes.chatroom,
      subject,
      latest.current.title,
    ).then(handled => {
      if (cancelled) return;

      if (handled) {
        latest.current.closePanel('followSession');
      } else {
        setDeclined(subject);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [isOpen, subject, declined]);

  const showOverlay = isOpen && !!subject && declined === subject;

  useEffect(() => {
    if (!showOverlay) return;

    return registerOverlay(() => closePanel('followSession'));
  }, [showOverlay, closePanel]);

  if (!showOverlay || !subject) return null;

  return (
    <Overlay subject={subject} onClose={() => closePanel('followSession')} />
  );
}

function Overlay({
  subject,
  onClose,
}: {
  subject: string;
  onClose: () => void;
}) {
  const chatroom = useResource(subject);

  return (
    <Screen data-testid='meeting-chat-overlay' role='dialog' aria-modal='true'>
      <Header>
        <Title resource={chatroom} />
        <IconButton title='Close chat' onClick={onClose} size='1.25em'>
          <FaXmark />
        </IconButton>
      </Header>
      <ChatRoomView resource={chatroom} noContainerPadding />
    </Screen>
  );
}

const Screen = styled.div`
  position: fixed;
  inset: 0 0 auto 0;
  height: min(
    calc(100dvh - var(--keyboard-inset, 0px)),
    var(--visible-viewport-height, 100dvh)
  );
  z-index: ${p => p.theme.zIndex.dialog};
  display: flex;
  flex-direction: column;
  box-sizing: border-box;
  padding: 0.25rem;
  background: ${p => p.theme.colors.bgBody};
`;

const Header = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  padding: ${p => p.theme.size(2)};
`;

const Title = styled(EditableTitle)`
  font-size: 1rem;
  margin: 0;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;
