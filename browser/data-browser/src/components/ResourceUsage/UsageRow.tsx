import { commits, unknownSubject, useResource } from '@tomic/react';

import { ResourceInline } from '../../views/ResourceInline';
import { styled } from 'styled-components';
import { ErrorLook } from '../ErrorLook';

interface UsageRowProps {
  subject: string;
}

export function UsageRow({ subject }: UsageRowProps): JSX.Element {
  const resource = useResource(subject);

  if (subject === unknownSubject) {
    return (
      <ListItem>
        <ErrorLook>Insufficient rights to view resource</ErrorLook>
      </ListItem>
    );
  }

  if (resource.hasClasses(commits.classes.commit)) {
    return <></>;
  }

  return (
    <ListItem>
      <ResourceInline subject={subject} />
    </ListItem>
  );
}

const ListItem = styled.li`
  display: flex;
  align-items: center;
  list-style: none;
  padding: 0.5rem 1rem;
  border-radius: ${({ theme }) => theme.radius};
  margin: 0;
  height: 3rem;
  &:nth-child(odd) {
    background-color: ${({ theme }) => theme.colors.bg1};
  }
`;
