import { FeedbackMenuItem } from '../components/SideBar/FeedbackMenuItem';
import { DialogGlobalContextProvider } from '../components/Dialog/DialogGlobalContextProvider';
import * as React from 'react';
import { Resource } from '@tomic/react';

import { ContainerWide } from '../components/Containers';
import { ErrorBlock } from '../components/ErrorLook';
import { Button } from '../components/Button';
import { Column, Row } from '../components/Row';

import type { JSX } from 'react';
import { styled } from 'styled-components';

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
    <StyledMain>
      <ContainerWide resource={resource?.subject}>
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
            <DialogGlobalContextProvider>
              <FeedbackMenuItem floating />
            </DialogGlobalContextProvider>
          </Row>
        </Column>
      </ContainerWide>
    </StyledMain>
  );
}

export default CrashPage;

const StyledMain = styled.main`
  height: 100dvh;
  overflow: auto;
`;
