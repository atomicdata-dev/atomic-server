import { styled } from 'styled-components';

export const InputBase = styled.input`
  position: absolute;
  inset: 0;
  padding-inline: var(--table-inner-padding);
  background-color: ${p => p.theme.colors.bg};
  color: ${p => p.theme.colors.text};
`;
