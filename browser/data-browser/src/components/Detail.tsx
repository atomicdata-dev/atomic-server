import { styled } from 'styled-components';

/** Small component showing some metadata. They appear next to each other. */
export const Detail = styled.div`
  display: inline-flex;
  align-items: center;
  gap: 1ch;
  margin-right: 2rem;
`;

/** A wrapper for the Detail component . */
export const Details = styled.div`
  font-style: italic;
  margin-bottom: 0.5rem;
  margin-top: -0.5rem;
`;
