import styled from 'styled-components';

/** Centered column */
export const ContainerNarrow = styled.div`
  max-width: ${props => props.theme.containerWidth}rem;
  margin: auto;
  padding: ${props => props.theme.margin}rem;
  // Extra space for the navbar below
  padding-bottom: 10rem;
`;

export const ContainerWide = styled.div`
  width: min(100%, ${props => props.theme.containerWidthWide});
  margin: auto;
  padding: ${props => props.theme.margin}rem;
  // Extra space for the navbar below
  padding-bottom: 10rem;
`;

/** Full-page wrapper */
export const ContainerFull = styled.div`
  padding: ${props => props.theme.margin}rem;
  padding-bottom: 10rem;
`;
