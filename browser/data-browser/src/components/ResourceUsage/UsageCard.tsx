import { Collection } from '@tomic/react';
import React from 'react';
import { styled } from 'styled-components';
import { Details } from '../Details';
import { UsageRow } from './UsageRow';
import { Column } from '../Row';

interface UsageCardProps {
  collection: Collection;
  title: string | React.ReactNode;
}

function mapOverCollection<T>(
  collection: Collection,
  mapFn: (index: number) => T,
): T[] {
  return new Array(Math.min(100, collection.totalMembers))
    .fill(0)
    .map((_, i) => mapFn(i));
}

export function UsageCard({ collection, title }: UsageCardProps): JSX.Element {
  return (
    <DetailsCard>
      <Details title={<>{title}</>}>
        <ContentWrapper>
          {collection.totalMembers > 100 && (
            <LimitMessage>
              Showing 100 of {collection.totalMembers}
            </LimitMessage>
          )}
          <List>
            {mapOverCollection(collection, i => (
              <UsageRow collection={collection} index={i} key={1} />
            ))}
          </List>
        </ContentWrapper>
      </Details>
    </DetailsCard>
  );
}

const DetailsCard = styled.div`
  border: 1px solid ${({ theme }) => theme.colors.bg2};
  border-radius: ${({ theme }) => theme.radius};
  padding: ${({ theme }) => theme.margin}rem;

  background-color: ${({ theme }) => theme.colors.bg};
`;

const List = styled.ul`
  margin: 0;
  padding: 0;
`;

const ContentWrapper = styled(Column)`
  margin-top: ${({ theme }) => theme.margin}rem;
`;

const LimitMessage = styled.span`
  text-align: end;
  color: ${({ theme }) => theme.colors.textLight};
`;
