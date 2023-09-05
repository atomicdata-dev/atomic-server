import { Resource, useTitle } from '@tomic/react';
import React from 'react';
import { AtomicLink } from './AtomicLink';
import styled from 'styled-components';

interface PageTitleProps {
  /** Put in front of the subject's name */
  prefix?: string;
  resource: Resource;
  /** Renders the Resources title as a clickable link */
  link?: boolean;
}

/**
 * An H1 heading title with the subject's name. Optionally makes it a clickable
 * link or adds a prefix. Use `EditableTitle` if you need editing capabilities.
 */
export function Title({ resource, prefix, link }: PageTitleProps): JSX.Element {
  const [title] = useTitle(resource);

  return (
    <H1>
      {prefix && `${prefix} `}
      {link ? (
        <AtomicLink subject={resource.getSubject()}>{title}</AtomicLink>
      ) : (
        title
      )}
    </H1>
  );
}

const H1 = styled.h1`
  margin-bottom: 0;
`;
