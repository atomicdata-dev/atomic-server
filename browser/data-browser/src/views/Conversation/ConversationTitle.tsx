import { core, useArray, useResource, useStore, useTitle } from '@tomic/react';
import type { Resource } from '@tomic/react';
import { Fragment } from 'react';

/** The names of a conversation's other members, as its title. A
 *  conversation has no name of its own: it is who you talk to. */
export function ConversationTitle({ resource }: { resource: Resource }) {
  const store = useStore();
  const [members] = useArray(resource, core.properties.read);
  const me = store.getAgent()?.subject;
  const others = members.filter(member => member !== me);

  if (others.length === 0) {
    return <>Only you</>;
  }

  return (
    <>
      {others.map((member, i) => (
        <Fragment key={member}>
          {i > 0 && ', '}
          <MemberName subject={member} />
        </Fragment>
      ))}
    </>
  );
}

function MemberName({ subject }: { subject: string }) {
  const resource = useResource(subject);
  const [title] = useTitle(resource);

  return <>{title || subject}</>;
}
