import React from 'react';
import styled from 'styled-components';
import { FaExternalLinkAlt } from 'react-icons/fa';

export enum ExternalLinkVariant {
  Plain,
  Button,
}

export interface ExternalLinkProps {
  to: string;
  variant?: ExternalLinkVariant;
}

export function ExternalLink({
  to,
  children,
  variant,
}: React.PropsWithChildren<ExternalLinkProps>): JSX.Element {
  const Comp =
    variant === ExternalLinkVariant.Button
      ? ExternalLinkButton
      : ExternalLinkPlain;

  return (
    <Comp href={to} target='_blank' rel='noreferrer'>
      {children}
      <FaExternalLinkAlt />
    </Comp>
  );
}

ExternalLink.defaultProps = {
  variant: ExternalLinkVariant.Plain,
};

const ExternalLinkPlain = styled.a`
  display: flex;
  align-items: center;
  gap: 0.5rem;
`;

const ExternalLinkButton = styled.a`
  padding-inline: 0.8rem;
  padding-block: 0.4rem;
  width: fit-content;
  background-color: ${props => props.theme.colors.bg};
  border: 1.5px solid ${props => props.theme.colors.main};
  border-radius: ${p => p.theme.radius};
  text-decoration: none;
  gap: 1ch;
  display: flex;
  align-items: center;
  font-weight: 600;
  justify-content: center;
  color: ${props => props.theme.colors.main};
  white-space: nowrap;
  transition: 0.1s transform, 0.1s background-color, 0.1s box-shadow, 0.1s color;

  &:hover,
  &:focus-within {
    background-color: ${props => props.theme.colors.main};
    color: white;
  }
`;
