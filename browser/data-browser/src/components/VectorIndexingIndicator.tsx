import { type JSX } from 'react';
import { styled } from 'styled-components';
import { Spinner } from './Spinner';

const Wrap = styled.span`
  display: inline-flex;
  width: 1.1rem;
  height: 1.1rem;
  flex-shrink: 0;
  vertical-align: middle;
  line-height: 0;
`;

/** Shown while the server is embedding vector index rows for this drive. */
export function VectorIndexingIndicator(): JSX.Element {
  return (
    <Wrap
      role='status'
      title='Indexing vector data for this drive. AI search may be briefly out of date.'
      aria-label='Indexing vector data for this drive. AI search may be briefly out of date.'
    >
      <Spinner size='1.1rem' />
    </Wrap>
  );
}
