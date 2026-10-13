import { styled } from 'styled-components';
import {
  core,
  dataBrowser,
  notifications,
  unknownSubject,
  useResource,
  useStore,
  useTitle,
} from '@tomic/react';
import { useInbox } from '../../hooks/useInbox';
import {
  groupNotifications,
  isUnread,
  markRead,
  occurredAt,
  type NotificationGroup,
} from '../../helpers/notifications/inbox';
import { formatTimeAgo } from '../../helpers/formatTimeAgo';
import { constructOpenURL } from '../../helpers/navigation';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { useRightPanel } from '../RightPanel/RightPanelContext';
import { AgentAvatar } from '../Presence/AgentAvatar';
import { Button } from '../Button';
import { Row } from '../Row';
import { LoaderBlock } from '../Loader';

/**
 * Everything in your Inbox, newest first: who said what where, one row per
 * conversation. Unread rows carry a dot; opening one reads it and takes you
 * to the conversation.
 */
export function NotificationList(): React.JSX.Element {
  const store = useStore();
  const { items, unread, loading } = useInbox();
  const navigate = useNavigateWithTransition();
  const { setPanelOpen } = useRightPanel();

  const open = async (group: NotificationGroup) => {
    // Replies can belong to a chat or a comment thread. The Message's `about`
    // distinguishes them; the notification kind alone cannot.
    const source = group.items[0]?.get(
      notifications.properties.notificationSource,
    );
    const reply =
      group.kind === 'reply' && typeof source === 'string'
        ? await store.getResource(source)
        : undefined;
    const openComments =
      group.kind === 'comment' || !!reply?.get(dataBrowser.properties.about);
    void markRead(
      store,
      group.items.map(n => n.subject),
    );
    if (!group.about) return;
    await navigate(constructOpenURL(group.about));

    if (openComments) {
      setPanelOpen('comments', true);
    }
  };

  const markAllRead = () =>
    void markRead(
      store,
      items.filter(isUnread).map(n => n.subject),
    );

  return (
    <Column>
      <Row center justify='space-between' wrapItems>
        <h1>Notifications</h1>
        {unread > 0 && (
          <Button subtle onClick={markAllRead}>
            Mark all as read
          </Button>
        )}
      </Row>
      {loading && items.length === 0 && <LoadingRows />}
      {!loading && items.length === 0 && (
        <Empty>
          Nothing yet. New messages in your chats, comments on your things and
          replies to you show up here.
        </Empty>
      )}
      <List aria-label='Notifications'>
        {groupNotifications(items).map(group => {
          const latest = group.items[0];

          return (
            <li key={group.key}>
              <Item
                type='button'
                onClick={() => void open(group)}
                data-unread={group.unread || undefined}
              >
                <AgentAvatar agentSubject={group.actors[0] ?? ''} size='2rem' />
                <Text>
                  <Title>
                    <Headline group={group} />
                  </Title>
                  <Body>
                    {latest.get(core.properties.description) as string}
                  </Body>
                </Text>
                <When>{formatTimeAgo(new Date(occurredAt(latest)))}</When>
                {group.unread && <Dot aria-label='Unread' />}
              </Item>
            </li>
          );
        })}
      </List>
    </Column>
  );
}

/** Placeholder rows until the list is known, so "Nothing yet" never flashes. */
function LoadingRows(): React.JSX.Element {
  return (
    <List aria-label='Loading notifications' aria-busy='true'>
      {[0, 1, 2].map(i => (
        <li key={i}>
          <SkeletonRow />
        </li>
      ))}
    </List>
  );
}

/** Who, what and where, written now: current names, the reader's language. */
function Headline({ group }: { group: NotificationGroup }): React.JSX.Element {
  const [first] = useTitle(useResource(group.actors[0] ?? unknownSubject));
  const [second] = useTitle(useResource(group.actors[1] ?? unknownSubject));
  const [on] = useTitle(useResource(group.about ?? unknownSubject));
  const count = group.items.length;
  const others = group.actors.length - 1;

  // Before the names load, or for kinds this version doesn't know, the text
  // the notification was stored with.
  const stored = group.items[0].get(core.properties.name) as string;

  if (!group.actors[0] || !first || !on) return <>{stored}</>;

  let who = first;

  if (others === 1) {
    who = `${first} and ${second}`;
  } else if (others > 1) {
    who = `${first} and ${others} others`;
  }

  switch (group.kind) {
    case 'chat':
      return count === 1 ? (
        <>{`${who} in ${on}`}</>
      ) : (
        <>{`${who}: ${count} new messages in ${on}`}</>
      );
    case 'comment':
      return count === 1 ? (
        <>{`${who} commented on ${on}`}</>
      ) : (
        <>{`${who}: ${count} comments on ${on}`}</>
      );
    case 'reply':
      return count === 1 ? (
        <>{`${who} replied to you in ${on}`}</>
      ) : (
        <>{`${who}: ${count} replies to you in ${on}`}</>
      );
    default:
      return <>{stored}</>;
  }
}

const Column = styled.div`
  display: flex;
  flex-direction: column;
  gap: ${p => p.theme.size(3)};
`;

const Empty = styled.p`
  color: ${p => p.theme.colors.textLight};
`;

const SkeletonRow = styled(LoaderBlock)`
  height: 3.25rem;
`;

const List = styled.ul`
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;

  & > li {
    list-style: none;
    margin: 0;
  }
`;

const Item = styled.button`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
  padding: 0.6rem 0.75rem;
  border: none;
  border-radius: ${p => p.theme.radius};
  background: transparent;
  color: ${p => p.theme.colors.text};
  text-align: left;
  cursor: pointer;

  &[data-unread] {
    background: ${p => p.theme.colors.bg1};
  }

  &:hover,
  &:focus-visible {
    background: ${p => p.theme.colors.bg2};
  }
`;

const Text = styled.span`
  display: flex;
  flex-direction: column;
  flex: 1;
  min-width: 0;
`;

/* Up to two lines: a grouped headline names people, a count and a place. */
const Title = styled.span`
  font-weight: 600;
  overflow: hidden;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;

  button:not([data-unread]) & {
    font-weight: 400;
  }
`;

const Body = styled.span`
  color: ${p => p.theme.colors.textLight};
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const When = styled.span`
  flex-shrink: 0;
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
`;

const Dot = styled.span`
  flex-shrink: 0;
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: ${p => p.theme.colors.main};
`;
