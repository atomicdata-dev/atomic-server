import { styled } from 'styled-components';

export const Slot = styled.div`
  grid-area: ${props => props.slot};
`;
