import React from 'react';
import { properties, useDate, useResource, useString } from '@tomic/react';
import { ResourceInline } from '../views/ResourceInline';
import { Detail } from './Detail';
import { DateTime } from './datatypes/DateTime';
import { AtomicLink } from './AtomicLink';

type Props = {
  commitSubject?: string;
};

/** Shows the latest editor and edit date */
export function CommitDetail({ commitSubject }: Props): JSX.Element | null {
  const resource = useResource(commitSubject);
  const [signer] = useString(resource, properties.commit.signer);
  const [previousCommit] = useString(
    resource,
    properties.commit.previousCommit,
  );
  const createdAt = useDate(resource, properties.commit.createdAt);

  if (!commitSubject) {
    return null;
  }

  if (!commitSubject || !resource.isReady) {
    return <Detail>loading...</Detail>;
  }

  return (
    <Detail>
      {signer && <ResourceInline subject={signer} />}
      {'-'}
      <AtomicLink subject={commitSubject}>
        {previousCommit ? 'edited ' : ''}
        {createdAt && <DateTime date={createdAt} />}
      </AtomicLink>{' '}
    </Detail>
  );
}
