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
          {clearError && <Button onClick={clearError}>Clear error</Button>}
          <Button
            onClick={() =>
              window.setTimeout(
                window.location.reload.bind(window.location),
                200,
              )
            }
          >
            Try Again
          </Button>
        </Row>
      </Column>
    </ContainerWide>
  );
}

export default CrashPage;
