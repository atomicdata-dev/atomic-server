import { ResourceInline } from '../views/ResourceInline';
import { Detail } from './Detail';
import { DateTime, DateTimeRelative } from './datatypes/DateTime';

import type { JSX } from 'react';

type Props = {
  short?: boolean;
  /**
   * Date read from the resource itself (genesis `createdAt`). No commit
   * fetch — `did:ad:commit:` is not a queryable resource.
   */
  createdAt?: Date;
  /**
   * Creator (an agent subject) read from the resource itself — e.g.
   * `useCreatedBy`, which derives it from the genesis certificate.
   */
  createdBy?: string;
};

/** Shows the editor and date from resource-derived metadata. */
export function CommitDetail({
  short,
  createdAt,
  createdBy,
}: Props): JSX.Element | null {
  if (!createdAt) {
    return null;
  }

  if (short) {
    return (
      <Detail>
        <DateTimeRelative date={createdAt} />
      </Detail>
    );
  }

  const dateElement = <DateTime date={createdAt} />;

  return (
    <Detail>
      {createdBy && <ResourceInline subject={createdBy} />}
      {'-'}
      {dateElement}{' '}
    </Detail>
  );
}
