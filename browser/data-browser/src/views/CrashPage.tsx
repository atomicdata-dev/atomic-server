import * as React from 'react';
import { Resource } from '@tomic/react';

import { ContainerWide } from '../components/Containers';
import { ErrorBlock } from '../components/ErrorLook';
import { Button } from '../components/Button';
import { Column, Row } from '../components/Row';

type ErrorPageProps = {
  resource?: Resource;
  children?: React.ReactNode;
  error: Error;
  info: React.ErrorInfo;
  clearError: () => void;
};

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

function createGithubIssueLink(error: Error): string {
  const url = new URL(
    'https://github.com/atomicdata-dev/atomic-data-browser/issues/new',
  );
  url.searchParams.set('body', githubIssueTemplate(error.message, error.stack));
  url.searchParams.set('labels', 'bug');

  return url.href;
}

/** If the entire app crashes, show this page */
function CrashPage({
  resource,
  children,
  error,
  clearError,
}: ErrorPageProps): JSX.Element {
  return (
    <ContainerWide resource={resource?.getSubject()}>
      <Column>
        {children ? children : <ErrorBlock error={error} showTrace />}
        <Row>
          <a href={createGithubIssueLink(error)}>Create Github issue</a>
          {clearError && <Button onClick={clearError}>Clear error</Button>}
          <Button
            onClick={() =>
              window.setTimeout(
                window.location.reload.bind(window.location),
                200,
              )
            }
          >
            Refresh page
          </Button>
        </Row>
      </Column>
    </ContainerWide>
  );
}

export default CrashPage;
