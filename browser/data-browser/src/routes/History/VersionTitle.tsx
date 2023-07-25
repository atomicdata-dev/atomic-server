import { Version, useResource, useTitle } from '@tomic/react';
import React from 'react';
import { AtomicLink } from '../../components/AtomicLink';

const formatter = new Intl.DateTimeFormat('default', {
  month: 'long',
  year: 'numeric',
  day: 'numeric',
  hour: 'numeric',
  minute: 'numeric',
  second: 'numeric',
});

export interface VersionTitleProps {
  version: Version;
}
export function VersionTitle({ version }: VersionTitleProps): JSX.Element {
  const signer = useResource(version.commit.signer);
  const [signerName] = useTitle(signer);

  const date = new Date(version.commit.createdAt);
  const formattedDate = formatter.format(date);

  return (
    <span>
      Editted <time dateTime={date.toISOString()}>{formattedDate}</time> by{' '}
      <AtomicLink subject={version.commit.signer}>{signerName}</AtomicLink>
    </span>
  );
}
