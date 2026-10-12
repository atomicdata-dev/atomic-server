import { useEffect, useRef } from 'react';
import toast from 'react-hot-toast';
import { styled } from 'styled-components';
import {
  core,
  dataBrowser,
  properties,
  unknownSubject,
  useCreatedBy,
  useCurrentAgent,
  useResource,
  useStore,
  useString,
  useTitle,
} from '@tomic/react';
import { useFollow } from './FollowContext';
import { AgentAvatar } from './AgentAvatar';
import { useRightPanel } from '../RightPanel/RightPanelContext';
import { useChatMessages } from '../../views/ChatRoom/ChatRoomView';
import {
  isFollowEntry,
  parseEntryId,
  readLogEntry,
} from '../../helpers/chatLog';
import { useChatLogEntry } from '../../hooks/useChatLog';

/**
 * Surfaces new meeting-chat messages as toasts when the meeting panel isn't
 * visible — on mobile, or whenever it's closed. Only while you're in a meeting
 * (leading or joined); skips your own messages and system trail events. Tapping
 * a toast opens the meeting panel. Renders nothing itself.
 */
export function MeetingMessageToaster(): null {
  const { followedSession, activeMeeting } = useFollow();
  const { activePanel, openMeetingPanel } = useRightPanel();
  const [agent] = useCurrentAgent();
  const store = useStore();

  const meeting = followedSession ?? activeMeeting;
  const panelOpen = activePanel === 'followSession';

  const { messages } = useChatMessages(meeting ?? unknownSubject);

  // How many messages we've already accounted for. Never toast the backlog.
  const seenRef = useRef(0);
  const meetingRef = useRef<string | undefined>(undefined);

  useEffect(() => {
    // Meeting changed (joined a new one, or left) → catch up silently.
    if (meeting !== meetingRef.current) {
      meetingRef.current = meeting;
      seenRef.current = messages.length;

      return;
    }

    // No meeting, or the panel is already showing it → nothing to announce.
    if (!meeting || panelOpen) {
      seenRef.current = messages.length;

      return;
    }

    if (messages.length <= seenRef.current) {
      return;
    }

    const fresh = messages.slice(seenRef.current);
    seenRef.current = messages.length;

    for (const subject of fresh) {
      // A message in the chat log: its author and kind are on the entry.
      if (parseEntryId(subject)) {
        const logged = readLogEntry(store, subject)?.entry;

        // System lines ("Viewing …", "Started/ended") and my own messages.
        if (isFollowEntry(logged) || logged?.a === agent?.subject) continue;

        toast.custom(
          t => (
            <MeetingToast
              subject={subject}
              onOpen={() => {
                openMeetingPanel(meeting);
                toast.dismiss(t.id);
              }}
            />
          ),
          { duration: 5000 },
        );
        continue;
      }

      const res = store.getResourceLoading(subject);
      const isA = (res.get(core.properties.isA) as string[] | undefined) ?? [];

      // Skip system trail events ("Viewing …", "Started/ended").
      if (isA.includes(dataBrowser.classes.followEvent)) {
        continue;
      }

      // Skip my own messages — I know what I just said.
      const author = res.get(properties.createdBy) as string | undefined;

      if (author && author === agent?.subject) {
        continue;
      }

      toast.custom(
        t => (
          <MeetingToast
            subject={subject}
            onOpen={() => {
              openMeetingPanel(meeting);
              toast.dismiss(t.id);
            }}
          />
        ),
        { duration: 5000 },
      );
    }
  }, [messages, panelOpen, meeting, agent, store, openMeetingPanel]);

  return null;
}

function MeetingToast({
  subject,
  onOpen,
}: {
  subject: string;
  onOpen: () => void;
}) {
  const resource = useResource(
    parseEntryId(subject) ? unknownSubject : subject,
  );
  const { entry } = useChatLogEntry(subject);
  const [resourceText] = useString(resource, core.properties.description);
  const resourceAuthor = useCreatedBy(resource);
  const text = entry ? entry.t : resourceText;
  const author = entry ? entry.a : resourceAuthor;
  const authorResource = useResource(author ?? unknownSubject);
  const [authorName] = useTitle(authorResource);

  return (
    <ToastCard type='button' onClick={onOpen} title='Open the meeting chat'>
      {author && <AgentAvatar agentSubject={author} size='1.8rem' />}
      <ToastBody>
        <ToastAuthor>{authorName}</ToastAuthor>
        <ToastText>{text}</ToastText>
      </ToastBody>
    </ToastCard>
  );
}

const ToastCard = styled.button`
  display: flex;
  align-items: center;
  gap: 0.6rem;
  max-width: 22rem;
  padding: 0.6rem 0.8rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg};
  box-shadow: ${p => p.theme.boxShadowSoft};
  cursor: pointer;
  text-align: left;
  color: ${p => p.theme.colors.text};
`;

const ToastBody = styled.span`
  display: flex;
  flex-direction: column;
  min-width: 0;
`;

const ToastAuthor = styled.span`
  font-weight: 600;
  font-size: 0.8rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const ToastText = styled.span`
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;
