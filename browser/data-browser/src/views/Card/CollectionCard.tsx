import { useArray, useString, useTitle, properties } from '@tomic/react';
import React, { useState } from 'react';

import Markdown from '../../components/datatypes/Markdown';
import { AtomicLink } from '../../components/AtomicLink';
import { CardInsideFull, CardRow } from '../../components/Card';
import { ResourceInline } from '../ResourceInline';
import { CardViewProps } from './CardViewProps';
import { Button } from '../../components/Button';

const MAX_COUNT = 5;

/**
 * Renders a Resource and all its Properties in a random order. Title
 * (shortname) is rendered prominently at the top.
 */
function CollectionCard({ resource, small }: CardViewProps): JSX.Element {
  const [title] = useTitle(resource);
  const [description] = useString(resource, properties.description);
  const [members] = useArray(resource, properties.collection.members);
  const [showAll, setShowMore] = useState(false);

  const tooMany = members.length > MAX_COUNT;
  let subjects = members;

  if (!showAll && tooMany) {
    subjects = subjects.slice(0, MAX_COUNT);
  }

  return (
    <React.Fragment>
      <AtomicLink subject={resource.getSubject()}>
        <h2>{title}</h2>
      </AtomicLink>
      {description && <Markdown text={description} />}
      {!small && (
        <CardInsideFull>
          {subjects.map(member => {
            return (
              <CardRow key={member}>
                <ResourceInline subject={member} />
              </CardRow>
            );
          })}
          {tooMany && (
            <CardRow>
              <Button clean onClick={() => setShowMore(!showAll)}>
                {showAll
                  ? 'show less'
                  : `show ${members.length - MAX_COUNT} more`}
              </Button>
            </CardRow>
          )}
        </CardInsideFull>
      )}
    </React.Fragment>
  );
}

export default CollectionCard;
