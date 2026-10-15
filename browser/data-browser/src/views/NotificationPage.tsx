import { useEffect } from 'react';
import {
  core,
  dataBrowser,
  notifications,
  unknownSubject,
  useStore,
  useNumber,
  useResource,
  useString,
  useTitle,
} from '@tomic/react';
import { ContainerNarrow } from '../components/Containers';
import Markdown from '../components/datatypes/Markdown';
import { AtomicLink } from '../components/AtomicLink';
import { Button } from '../components/Button';
import { Row } from '../components/Row';
import { formatTimeAgo } from '../helpers/formatTimeAgo';
import { actorName } from '../helpers/notifications/actorName';
import { markRead } from '../helpers/notifications/inbox';
import { paths } from '../routes/paths';
import { constructOpenURL } from '../helpers/navigation';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { useRightPanel } from '../components/RightPanel/RightPanelContext';
import { ResourcePageProps } from './ResourcePage';

/** One Notification: who did what where, and a way to go there. */
export function NotificationPage({
  resource,
}: ResourcePageProps): React.JSX.Element {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const { setPanelOpen } = useRightPanel();
  const [actor] = useString(resource, notifications.properties.actor);
  const [about] = useString(resource, dataBrowser.properties.about);
  const [kind] = useString(resource, notifications.properties.notificationKind);
  const [occurredAt] = useNumber(resource, notifications.properties.occurredAt);
  const [body] = useString(resource, core.properties.description);
  const [stored] = useString(resource, core.properties.name);
  const [actorTitle] = useTitle(useResource(actor ?? unknownSubject));
  const [target] = useTitle(useResource(about ?? unknownSubject));

  // Opening a notification reads it.
  useEffect(() => {
    void markRead(store, [resource.subject]).catch(e =>
      console.error('Could not mark the notification read:', e),
    );
  }, [store, resource.subject]);

  const who = actorName(actorTitle, actor) ?? 'Someone';

  let headline = stored ?? '';

  if (target) {
    if (kind === 'comment') headline = `${who} commented on ${target}`;
    else if (kind === 'reply') headline = `${who} replied to you in ${target}`;
    else if (kind === 'chat') headline = `${who} in ${target}`;
  }

  const open = () => {
    if (!about) return;
    navigate(constructOpenURL(about));
    if (kind === 'comment') setPanelOpen('comments', true);
  };

  return (
    <ContainerNarrow>
      <h2>{headline}</h2>
      {occurredAt !== undefined && <p>{formatTimeAgo(new Date(occurredAt))}</p>}
      <Markdown text={body || ''} />
      <Row>
        {about && <Button onClick={open}>Open conversation</Button>}
        <AtomicLink path={paths.notifications}>All notifications</AtomicLink>
      </Row>
    </ContainerNarrow>
  );
}
