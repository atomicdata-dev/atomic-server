import type { PropsWithChildren } from 'react';
import { styled } from 'styled-components';
import { lighten } from 'polished';

export function WarningBlock({
  children,
}: PropsWithChildren): React.JSX.Element {
  return <Wrapper>{children}</Wrapper>;
}

const Wrapper = styled.div`
  background-color: ${p => lighten(0.4, p.theme.colors.warning)};
  border: 2px solid ${p => lighten(0.2, p.theme.colors.warning)};
  border-radius: ${p => p.theme.radius};
  padding: 1rem;
`;

WarningBlock.Title = styled.p`
  font-weight: bold;
  color: ${p => lighten(-1, p.theme.colors.warning)};
  margin-bottom: 0px;
`;
