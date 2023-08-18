import { styled } from 'styled-components';
import React from 'react';

export function SkipNav(): JSX.Element {
  return <SkipLink href='#skip-to-content'>Skip Navigation?</SkipLink>;
}

const SkipLink = styled.a`
  display: flex;
  justify-content: center;
  align-items: center;
  --skip-button-width: min(90vw, 20rem);
  position: absolute;
  width: 100vw;
  background: ${({ theme }) => theme.colors.main};
  z-index: 100;
  box-shadow: ${({ theme }) => theme.boxShadowSoft};
  border: none;
  padding: 1rem;
  color: white;
  font-size: 1.5rem;
  pointer-events: none;
  top: -10rem;

  &:focus {
    top: 1rem;
  }
`;
