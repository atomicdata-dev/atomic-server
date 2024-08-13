import React from 'react';
import { ButtonDefault } from './Button';
import styled from 'styled-components';

export function ButtonLink(
  props: React.AnchorHTMLAttributes<HTMLAnchorElement>,
): React.JSX.Element {
  return (
    <StyledButtonDefault as='a' {...props}>
      {props.children}
    </StyledButtonDefault>
  );
}

const StyledButtonDefault = styled(ButtonDefault)`
  text-decoration: none;
`;
