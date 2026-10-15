import { useEffect, useRef } from 'react';
import toast from 'react-hot-toast';
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
import {
  ToastBody,
  ToastCard,
  ToastText,
  ToastTitle,
} from '../Notifications/toastStyles';

/**
 * Surfaces new meeting-chat messages as toasts when the meeting panel isn't
 * visible — on mobile, or whenever it's closed. Only while you're in a meeting
 * (leading or joined); skips your own messages and system trail events. Tapping
 * a toast opens the meeting panel. Renders nothing itself.
 */
export function MeetingMessageToaster(): null {
  const { followedSession, activeMeeting } = useFollow();
  const { activePanel, selectedMeeting, openMeetingPanel } = useRightPanel();
  const [agent] = useCurrentAgent();
  const store = useStore();

  const meeting = followedSession ?? activeMeeting;
  // The panel shows `selectedMeeting` when one was picked, else the meeting
  // we are in (FollowSessionPanelContainer). Only that chat is on screen.
  const panelOpen =
    activePanel === 'followSession' && (selectedMeeting ?? meeting) === meeting;

  const { messages } = useChatMessages(meeting ?? unknownSubject);

  // How many messages we've already accounted for. Never toast the backlog.
  const seenRef = useRef(0);
  const meetingRef = useRef<string | undefined>(undefined);
  // When we started watching this meeting. A list that loads in batches would
  // otherwise pass its backlog off as new messages, so only entries made after
  // this count.
  const sinceRef = useRef(0);
  // The toasts on screen, so opening the panel can take them away: the
  // messages they show are in the panel now.
  const shownRef = useRef(new Set<string>());

  useEffect(() => {
    if (!panelOpen) return;

    for (const id of shownRef.current) toast.dismiss(id);
    shownRef.current.clear();
  }, [panelOpen]);

  useEffect(() => {
    // Meeting changed (joined a new one, or left) → catch up silently.
    if (meeting !== meetingRef.current) {
      meetingRef.current = meeting;
      seenRef.current = messages.length;
      sinceRef.current = Date.now();

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

        // Written before we started watching: backlog that loaded late.
        if (logged && logged.c < sinceRef.current) continue;

        show(subject, meeting);
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

      const createdAt = res.getCreatedAt();

      if (createdAt !== undefined && createdAt < sinceRef.current) continue;

      show(subject, meeting);
    }

    function show(subject: string, room: string) {
      const id = toast.custom(
        t => (
          <MeetingToast
            subject={subject}
            onOpen={() => {
              openMeetingPanel(room);
              toast.dismiss(t.id);
            }}
          />
        ),
        { duration: 5000 },
      );
      shownRef.current.add(id);
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
        <ToastTitle>{authorName}</ToastTitle>
        <ToastText>{text}</ToastText>
      </ToastBody>
    </ToastCard>
  );
}
