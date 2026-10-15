import {
  core,
  useArray,
  useResource,
  useResources,
  useStore,
  useTitle,
} from '@tomic/react';
import type { Resource } from '@tomic/react';
import { Fragment, useMemo } from 'react';

/** The members of a conversation other than the signed-in agent. */
export function useOtherMembers(resource: Resource): string[] {
  const store = useStore();
  const [members] = useArray(resource, core.properties.read);
  const me = store.getAgent()?.subject;

  return members.filter(member => member !== me);
}

/** The names of a conversation's other members, for matching a search. */
export function useMemberNames(resource: Resource): string[] {
  const others = useOtherMembers(resource);
  // `useResources` needs a stable array.
  const key = others.join(' ');
  const subjects = useMemo(() => (key ? key.split(' ') : []), [key]);
  const resources = useResources(subjects);

  return subjects.map(subject => resources.get(subject)?.title ?? subject);
}

/** The names of a conversation's other members, as its title. A
 *  conversation has no name of its own: it is who you talk to. */
export function ConversationTitle({ resource }: { resource: Resource }) {
  const others = useOtherMembers(resource);

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
