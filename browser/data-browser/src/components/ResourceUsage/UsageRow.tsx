import {
  Collection,
  classes,
  unknownSubject,
  useMemberFromCollection,
} from '@tomic/react';
import React from 'react';
import { ResourceInline } from '../../views/ResourceInline';
import { styled } from 'styled-components';
import { ErrorLook } from '../ErrorLook';

interface UsageRowProps {
  collection: Collection;
  index: number;
}

export function UsageRow({ collection, index }: UsageRowProps): JSX.Element {
  const resource = useMemberFromCollection(collection, index);

  if (resource.getSubject() === unknownSubject) {
    return (
      <ListItem>
        <ErrorLook>Insufficient rights to view resource</ErrorLook>
      </ListItem>
    );
  }

  if (resource.hasClasses(classes.commit)) {
    return <></>;
  }

  return (
    <ListItem>
      <ResourceInline subject={resource.getSubject()} />
    </ListItem>
  );
}

const ListItem = styled.li`
  list-style: none;
  padding: 0.5rem 1rem;
  border-radius: ${({ theme }) => theme.radius};

  margin-left: 0;

  &:nth-child(odd) {
    background-color: ${({ theme }) => theme.colors.bg1};
  }
`;
