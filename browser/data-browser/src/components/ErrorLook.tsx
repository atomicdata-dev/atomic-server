import { lighten } from 'polished';
import { styled, css } from 'styled-components';

import { FaExclamationTriangle } from 'react-icons/fa';
import { Column } from './Row';
import { CodeBlock } from './CodeBlock';

export const errorLookStyle = css`
  color: ${props => props.theme.colors.alert};
  font-family: monospace;
  line-height: 1.2rem;
`;

export const ErrorLook = styled.span`
  ${errorLookStyle}
`;

export interface ErrorBlockProps {
  error: Error;
  showTrace?: boolean;
}

export function ErrorBlock({ error, showTrace }: ErrorBlockProps): JSX.Element {
  return (
    <ErrorLookBig>
      <BiggerText>
        <FaExclamationTriangle />
        Something went wrong
      </BiggerText>
      <Column>
        <CodeBlock content={error.message || 'no error message available'} />
        {showTrace && (
          <>
            Stack trace:
            <CodeBlock content={error.stack || 'no stack trace available'} />
          </>
        )}
      </Column>
    </ErrorLookBig>
  );
}

const ErrorLookBig = styled.div`
  font-size: 1rem;
  padding: ${p => p.theme.margin}rem;
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => lighten(0.2, p.theme.colors.alert)};
  background-color: ${p => p.theme.colors.bg};
`;

const Pre = styled.pre`
  white-space: pre-wrap;
  border-radius: ${p => p.theme.radius};
  padding: ${p => p.theme.margin}rem;
  background-color: ${p => p.theme.colors.bg};
  font-size: 0.9rem;
`;

const BiggerText = styled.p`
  color: ${p => p.theme.colors.alert};
  font-size: 1.3rem;
  display: flex;
  align-items: center;
  gap: 1ch;
`;
