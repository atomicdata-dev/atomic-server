import { useMemo } from 'react';
import {
  useDrivePresence,
  useResource,
  useStore,
  useTitle,
} from '@tomic/react';
import { FaEnvelope, FaLocationArrow, FaUser } from 'react-icons/fa6';
import { DropdownMenu, type DropdownItem } from '../Dropdown';
import type { DropdownTriggerProps } from '../Dropdown/DropdownTrigger';
import { AgentAvatar } from './AgentAvatar';
import { FollowingIndicator } from './FollowingIndicator';
import { useFollow } from './FollowContext';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../../helpers/navigation';
import { findOrStartConversation } from '../../helpers/conversations/useConversations';

interface PresenceAvatarMenuProps {
  agentSubject: string;
  /** Avatar diameter, forwarded to {@link AgentAvatar}. */
  size?: string;
  /** Whether hovering a followed avatar grows the "Following" chip. Off
   *  where the avatar sits in a column of content (chat messages): the chip
   *  widened the avatar and pushed the message text aside. The blue ring
   *  and the menu still say it. */
  chip?: boolean;
}

/**
 * A presence avatar that opens a context menu on click: show the agent's
 * profile, or — when they're online and followable — follow them around the
 * drive (issue #1229). An online agent gets a green presence dot. Used
 * everywhere an agent avatar appears (facepiles, chat) so the menu is
 * consistent. Renders as a focusable span so it stays valid markup inside
 * sidebar row links. While following, the avatar uses the shared tight
 * blue ring + hover "Following" chip (issue #1486).
 */
export function PresenceAvatarMenu({
  agentSubject,
  size,
  chip = true,
}: PresenceAvatarMenuProps): React.JSX.Element {
  const navigate = useNavigateWithTransition();
  const store = useStore();
  const isMe = store.getAgent()?.subject === agentSubject;
  const { followedAgent, follow, unfollow, isFollowDisabledFor } = useFollow();
  const presence = useDrivePresence();
  const agentResource = useResource(agentSubject);
  const [name] = useTitle(agentResource);
  const isFollowing = followedAgent === agentSubject;
  const followDisabled = isFollowDisabledFor(agentSubject);
  const online = useMemo(
    () => presence.some(item => item.agent === agentSubject),
    [presence, agentSubject],
  );

  const items = useMemo((): DropdownItem[] => {
    const result: DropdownItem[] = [
      {
        id: 'show-profile',
        label: 'Show profile',
        icon: <FaUser />,
        onClick: () => navigate(constructOpenURL(agentSubject)),
      },
    ];

    if (!isMe) {
      result.push({
        id: 'message',
        label: 'Message',
        icon: <FaEnvelope />,
        onClick: () => {
          findOrStartConversation(store, [agentSubject])
            .then(subject => navigate(constructOpenURL(subject)))
            .catch(error => store.notifyError(error));
        },
      });
    }

    // Presence excludes this tab's own session, so even the same agent subject
    // represents another live tab or device that can be followed.
    if (isFollowing) {
      result.push({
        id: 'follow',
        label: 'Stop following',
        icon: <FaLocationArrow />,
        onClick: unfollow,
      });
    } else if (online && !followDisabled) {
      result.push({
        id: 'follow',
        label: 'Follow',
        icon: <FaLocationArrow />,
        onClick: () => follow(agentSubject),
      });
    }

    return result;
  }, [
    agentSubject,
    isMe,
    store,
    isFollowing,
    online,
    followDisabled,
    navigate,
    follow,
    unfollow,
  ]);

  const Trigger = useMemo(
    () =>
      buildPresenceTrigger(agentSubject, name, size, isFollowing, online, chip),
    [agentSubject, name, size, isFollowing, online, chip],
  );

  return <DropdownMenu items={items} Trigger={Trigger} />;
}

const buildPresenceTrigger = (
  agentSubject: string,
  name: string,
  size: string | undefined,
  following: boolean,
  online: boolean,
  chip: boolean,
): React.FC<DropdownTriggerProps> => {
  const Comp = (props: DropdownTriggerProps) => (
    <FollowingIndicator
      {...props}
      following={following}
      chip={chip}
      title={following ? 'Following — press for actions' : name}
      ariaLabel={following ? `Following ${name}` : name}
    >
      <AgentAvatar
        agentSubject={agentSubject}
        size={size}
        online={online}
        following={following}
      />
    </FollowingIndicator>
  );

  Comp.displayName = 'PresenceAvatarTrigger';

  return Comp;
};
