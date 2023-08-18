import { useResource } from '@tomic/react';
import React from 'react';
import { styled } from 'styled-components';

interface InlineOverlayProps {
  subject: string;
}

export function InlineOverlay({ subject }: InlineOverlayProps): JSX.Element {
  const resource = useResource(subject, { allowIncomplete: true });
  const valid = !(resource.error || resource.loading);

  return <Wrapper valid={valid}>{resource.title}</Wrapper>;
}

const Wrapper = styled.span<{ valid: boolean }>`
  /* Since the overlay is rendered in an input we shift it by one pixel to prevent layout shift when typing */
  margin-left: 1px;
  color: ${p => (p.valid ? p.theme.colors.main : 'currentColor')};
`;
