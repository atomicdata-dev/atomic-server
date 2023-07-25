import React from 'react';
import styled from 'styled-components';
import { displayShortcut } from './HotKeyWrapper';

export interface ShortcutProps {
  shortcut: string;
  className?: string;
}

export function Shortcut({ shortcut, className }: ShortcutProps): JSX.Element {
  const parts = displayShortcut(shortcut).split('+');

  return (
    <Wrapper className={className}>
      {parts.map((part, i) => (
        <React.Fragment key={i}>
          <KBD>{part}</KBD> {i < parts.length - 1 && '+ '}
        </React.Fragment>
      ))}
    </Wrapper>
  );
}

const Wrapper = styled.span`
  font-size: 10px;
`;

const KBD = styled.kbd`
  display: inline-block;
  border: ${p => p.theme.colors.bg2} solid 1px;
  background-color: ${p => p.theme.colors.bg1};
  text-transform: capitalize;
  border-radius: 5px;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI Adjusted',
    'Segoe UI', 'Liberation Sans', sans-serif;
  padding: 0.3em;
`;
