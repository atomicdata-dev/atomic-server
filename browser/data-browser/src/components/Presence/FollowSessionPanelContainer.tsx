import { lazy, Suspense, useMemo, useState } from 'react';
import { useCurrentAgent, useDrivePresence, useResource } from '@tomic/react';
import { styled, css } from 'styled-components';
import { FaNoteSticky, FaVideo } from 'react-icons/fa6';
import { RightPanel } from '../RightPanel/RightPanel';
import { useContextualPanel } from '../RightPanel/useContextualPanel';
import { useRightPanel } from '../RightPanel/RightPanelContext';
import { useFollow } from './FollowContext';
import { PresenceAvatarMenu } from './PresenceAvatarMenu';
import { ChatRoomView } from '../../views/ChatRoom/ChatRoomView';
import { EditableTitle } from '../EditableTitle';
import { MEETING_PANEL_TITLE_TRANSITION_TAG } from '../../helpers/transitionName';
import { Column, Row } from '../Row';
import { AtomicLink } from '../AtomicLink';
import { Button, ButtonSubtle } from '../Button';

const ConferenceRoom = lazy(
  () => import('../../chunks/Conference/ConferenceRoom'),
);

/**
 * Right-side panel with the live meeting: who's here, the trail of
 * resources the leader visits, plus chat. Shows the meeting you've
 * joined (following its leader) or the one you're leading.
 */
export const FollowSessionPanelContainer: React.FC = () => {
  const { followedSession, activeMeeting } = useFollow();
  const { selectedMeeting } = useRightPanel();
  const subject = selectedMeeting ?? followedSession ?? activeMeeting;
  const isOpen = useContextualPanel('followSession', subject);

  return (
    <RightPanel isOpen={isOpen} testId='follow-session-panel'>
      {isOpen && subject && (
        <FollowSessionChat subject={subject} key={subject} />
      )}
    </RightPanel>
  );
};

function FollowSessionChat({ subject }: { subject: string }) {
  const chatroom = useResource(subject);
  const { followedAgent, unfollow, activeMeeting, endMeeting } = useFollow();
  const { setPanelOpen } = useRightPanel();
  const presence = useDrivePresence();
  const [agent] = useCurrentAgent();
  const [ending, setEnding] = useState(false);
  const [inCall, setInCall] = useState(false);

  // The panel header's action: the leader ends the meeting; a joined
  // attendee leaves it.
  const leading = activeMeeting === subject;
  const label = leading ? 'End' : 'Leave';

  // Who else is in the meeting: the leader (whoever announces this
  // meeting as their `session`) plus everyone following that leader,
  // plus me when I'm taking part.
  const leaderAgent = leading
    ? agent?.subject
    : presence.find(item => item.session === subject)?.agent;

  const participants = useMemo(() => {
    const set = new Set<string>();

    if (leaderAgent) set.add(leaderAgent);

    for (const item of presence) {
      if (item.session === subject) set.add(item.agent);
      if (leaderAgent && item.following === leaderAgent) set.add(item.agent);
    }

    if (
      agent?.subject &&
      (leading || (!!leaderAgent && followedAgent === leaderAgent))
    ) {
      set.add(agent.subject);
    }

    return [...set];
  }, [presence, subject, leaderAgent, agent, leading, followedAgent]);

  async function handleAction() {
    if (leading) {
      setEnding(true);
      await endMeeting();
      setEnding(false);

      return;
    }

    unfollow();
    setPanelOpen('followSession', false);
  }

  // Only leader / joined attendee gets the End / Leave action.
  const showAction = leading || followedAgent === leaderAgent;

  return (
    <PanelWrapper>
      <PanelHeader center justify='space-between'>
        <TitleRow center gap='0.5rem'>
          <PanelTitle
            resource={chatroom}
            transitionTag={MEETING_PANEL_TITLE_TRANSITION_TAG}
          />
          {participants.length > 0 && (
            <Facepile title={`${participants.length} here`}>
              {participants.slice(0, 5).map(subj => (
                <PresenceAvatarMenu
                  key={subj}
                  agentSubject={subj}
                  size='1.5rem'
                />
              ))}
              {participants.length > 5 && (
                <Overflow>+{participants.length - 5}</Overflow>
              )}
            </Facepile>
          )}
        </TitleRow>
        <ButtonRow center gap='0.5rem'>
          <CallToggleButton
            $active={inCall}
            onClick={() => setInCall(current => !current)}
            title={inCall ? 'Leave video call' : 'Start video call'}
          >
            <FaVideo />
          </CallToggleButton>
          <NotesButton as={AtomicLink} subject={subject} clean title='Notes'>
            <FaNoteSticky />
          </NotesButton>
          {showAction && (
            <Button subtle onClick={handleAction} disabled={ending}>
              {ending ? 'Ending…' : label}
            </Button>
          )}
        </ButtonRow>
      </PanelHeader>
      {inCall && (
        <Suspense fallback={<CallFallback>Connecting to call…</CallFallback>}>
          <ConferenceRoom subject={subject} onLeave={() => setInCall(false)} />
        </Suspense>
      )}
      <ChatRoomView resource={chatroom} noContainerPadding />
    </PanelWrapper>
  );
}

const PanelWrapper = styled(Column)`
  height: 100%;
  gap: 0;
`;

const PanelHeader = styled(Row)`
  padding-block: ${p => p.theme.size(2)};
`;

/** Shrinks to make room for ButtonRow; the panel is narrow by nature, so the
 *  title — not the actions — gives way first, truncating with an ellipsis. */
const TitleRow = styled(Row)`
  min-width: 0;
  flex: 1 1 auto;
  overflow: hidden;
`;

/** Icon-only actions, so they keep their size and the title truncates
 *  instead of squishing them. */
const ButtonRow = styled(Row)`
  flex-shrink: 0;
`;

/** The meeting name, click-to-edit. */
const PanelTitle = styled(EditableTitle)`
  font-size: 1rem;
  margin: 0;
  min-width: 0;
  width: auto;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

/**
 * AtomicLink's own `LinkView` styling (blue text) has the same CSS
 * specificity as ButtonSubtle's, and wins ties based on style-sheet
 * insertion order. The `&&` doubles our selector's specificity so the
 * button look always wins regardless of that order.
 */
const NotesButton = styled(ButtonSubtle)`
  && {
    color: var(--button-text-color);
    text-decoration: none;

    &:hover,
    &:focus-visible {
      color: var(--button-text-color-hover);
    }
  }
`;

/** Icon-only toggle for the p2p video call; highlighted while in a call. */
const CallToggleButton = styled(ButtonSubtle)<{ $active: boolean }>`
  ${p =>
    p.$active &&
    css`
      && {
        color: ${p.theme.colors.main};
      }
    `}
`;

const CallFallback = styled.span`
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
  text-align: center;
  padding-block: ${p => p.theme.size(2)};
`;

const Facepile = styled.span`
  display: inline-flex;
  align-items: center;

  & > *:not(:first-child) {
    margin-left: -0.4rem;
  }
`;

const Overflow = styled.span`
  margin-left: 0.15rem;
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
`;
