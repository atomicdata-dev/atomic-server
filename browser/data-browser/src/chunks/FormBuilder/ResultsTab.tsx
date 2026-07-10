import { Resource, unknownSubject } from '@tomic/react';
import type { JSX } from 'react';
import { styled } from 'styled-components';
import { TableResource } from '@chunks/TablePage/TableResource';

interface ResultsTabProps {
  tableResource: Resource;
}

/**
 * Renders the target table's grid via the same `TableResource` component
 * every other table view uses — it has its own reliable empty state, so
 * this doesn't duplicate that logic with a second, independently-timed
 * `useCollection` query (see `useSubmissionCount`'s doc comment for why
 * that duplication was unreliable and got dropped).
 */
export function ResultsTab({ tableResource }: ResultsTabProps): JSX.Element {
  if (tableResource.subject === unknownSubject) {
    return <EmptyState>No results table found for this form.</EmptyState>;
  }

  return <TableResource resource={tableResource} />;
}

const EmptyState = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: ${p => p.theme.colors.textLight};
  text-align: center;
  padding: ${p => p.theme.size(4)};
`;
