import { lighten } from 'polished';
import { styled, css } from 'styled-components';

import { FaExclamationTriangle } from 'react-icons/fa';
import { Column } from './Row';
import { CodeBlock } from './CodeBlock';
import { Button } from './Button';

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

const githubIssueTemplate = (
  message,
  stack,
) => `**Describe what you did to produce the bug**

## Error message
\`\`\`
${message}
\`\`\`

## Stack trace
\`\`\`
${stack}
\`\`\`
`;

/** Returns github URL for new bugs */
export function createGithubIssueLink(error: Error): string {
  const url = new URL(
    'https://github.com/atomicdata-dev/atomic-server/issues/new',
  );
  url.searchParams.set('body', githubIssueTemplate(error.message, error.stack));
  url.searchParams.set('labels', 'bug');

  console.log('opening', url);

  return url.href;
}

export function GitHubIssueButton({ error }) {
  return (
    <Button onClick={() => window.open(createGithubIssueLink(error), '_blank')}>
      Report on Github
    </Button>
  );
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

const BiggerText = styled.p`
  color: ${p => p.theme.colors.alert};
  font-size: 1.3rem;
  display: flex;
  align-items: center;
  gap: 1ch;
`;
