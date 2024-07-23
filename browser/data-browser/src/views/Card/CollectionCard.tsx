import { useArray, useString, core, collections } from '@tomic/react';
import { FC, PropsWithChildren, useState } from 'react';

import Markdown from '../../components/datatypes/Markdown';
import { CardInsideFull, CardRow } from '../../components/Card';
import { ResourceInline } from '../ResourceInline';
import { CardViewProps } from './CardViewProps';
import { Button } from '../../components/Button';
import { ResourceCardTitle } from './ResourceCardTitle';
import { Column } from '../../components/Row';
import { styled } from 'styled-components';

const MAX_COUNT = 5;

/**
 * Renders a Resource and all its Properties in a random order. Title
 * (shortname) is rendered prominently at the top.
 */
function CollectionCard({ resource }: CardViewProps): JSX.Element {
  const [description] = useString(resource, core.properties.description);
  const [members] = useArray(resource, collections.properties.members);
  const [showAll, setShowMore] = useState(false);

  const tooMany = members.length > MAX_COUNT;
  let subjects = members;

  if (!showAll && tooMany) {
    subjects = subjects.slice(0, MAX_COUNT);
  }

  return (
    <Column gap='0.5rem'>
      <ResourceCardTitle resource={resource} />
      {description && <Markdown text={description} />}
      {subjects.length === 0 ? (
        <Empty>No resources</Empty>
      ) : (
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
    </Column>
  );
}

const Empty = styled.span`
  color: ${({ theme }) => theme.colors.textLight};
`;

export default CollectionCard;
