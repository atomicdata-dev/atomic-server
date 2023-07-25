import React from 'react';
import { useString, useResource, useTitle, urls, Client } from '@tomic/react';
import { AtomicLink } from '../components/AtomicLink';
import { ErrorLook } from '../components/ErrorLook';
import { LoaderInline } from '../components/Loader';

type Props = {
  subject: string;
  untabbable?: boolean;
  className?: string;
};

/** Renders a Resource in a compact, inline link. Shows tooltip on hover. */
export function ResourceInline({
  subject,
  untabbable,
  className,
}: Props): JSX.Element {
  const resource = useResource(subject, { allowIncomplete: true });
  const [title] = useTitle(resource);
  const [description] = useString(resource, urls.properties.description);

  if (!subject) {
    return <ErrorLook>No subject passed</ErrorLook>;
  }

  if (resource.error) {
    return (
      <AtomicLink subject={subject} untabbable={untabbable}>
        <ErrorLook about={subject} title={resource.error.message}>
          Unknown Resource
        </ErrorLook>
      </AtomicLink>
    );
  }

  if (resource.loading) {
    return <LoaderInline about={subject} title={`${subject} is loading..`} />;
  }

  if (!Client.isValidSubject(subject)) {
    return <ErrorLook>{subject} is not a valid subject.</ErrorLook>;
  }

  return (
    <AtomicLink subject={subject} untabbable={untabbable} className={className}>
      <span title={description ? description : ''}>{title}</span>
    </AtomicLink>
  );
}
