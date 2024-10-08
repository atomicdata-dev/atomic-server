import { styled } from 'styled-components';

/** Small component showing some metadata. They appear next to each other. */
export const Detail = styled.div`
  display: inline-flex;
  align-items: center;
  gap: 0.5ch;
  margin-right: 2rem;
`;

/** A wrapper for the Detail component . */
export const Details = styled.div`
  font-style: italic;
`;
