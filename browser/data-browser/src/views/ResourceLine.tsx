import React from 'react';
import { urls, useString, useResource, useTitle } from '@tomic/react';
import { ResourceInline } from './ResourceInline';
import { ErrorLook } from '../components/ErrorLook';

type Props = {
  subject: string;
  clickable?: boolean;
};

/** Renders a Resource in a small line item. Not a link. Useful in dropdown. */
function ResourceLine({ subject, clickable }: Props): JSX.Element {
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  let [description] = useString(resource, urls.properties.description);

  if (resource.loading) {
    return <span about={subject}>Loading...</span>;
  }

  if (resource.error) {
    return (
      <ErrorLook about={subject}>Error: {resource.error.message}</ErrorLook>
    );
  }

  const TRUNCATE_LENGTH = 40;

  if (description && description.length >= TRUNCATE_LENGTH) {
    description = description.slice(0, TRUNCATE_LENGTH) + '...';
  }

  return (
    <span about={subject}>
      {clickable ? (
        <ResourceInline untabbable subject={subject} />
      ) : (
        <b>{title}</b>
      )}
      {description ? ` - ${description}` : null}
    </span>
  );
}

export default ResourceLine;
