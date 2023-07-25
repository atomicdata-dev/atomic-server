import * as React from 'react';
import { isUnauthorized, useStore } from '@tomic/react';
import { ContainerWide } from '../components/Containers';
import { ErrorBlock } from '../components/ErrorLook';
import { Button } from '../components/Button';
import { SignInButton } from '../components/SignInButton';
import { useSettings } from '../helpers/AppSettings';
import { ResourcePageProps } from './ResourcePage';
import { Column, Row } from '../components/Row';
import CrashPage from './CrashPage';

/**
 * A View for Resource Errors. Not to be confused with the CrashPage, which is
 * for App wide errors.
 */
function ErrorPage({ resource }: ResourcePageProps): JSX.Element {
  const { agent } = useSettings();
  const store = useStore();
  const subject = resource.getSubject();

  if (isUnauthorized(resource.error)) {
    return (
      <ContainerWide>
        <Column>
          <h1>Unauthorized</h1>
          {agent ? (
            <>
              <ErrorBlock error={resource.error!} />
              <span>
                <Button onClick={() => store.fetchResourceFromServer(subject)}>
                  Retry
                </Button>
              </span>
            </>
          ) : (
            <>
              <p>{"You don't have access to this, try signing in:"}</p>
              <SignInButton />
            </>
          )}
        </Column>
      </ContainerWide>
    );
  }

  return (
    <ContainerWide>
      <Column>
        <h1>Could not open {resource.getSubject()}</h1>
        <ErrorBlock error={resource.error!} />
        <Row>
          <Button
            onClick={() =>
              store.fetchResourceFromServer(subject, { setLoading: true })
            }
          >
            Retry
          </Button>
          <Button
            onClick={() =>
              store.fetchResourceFromServer(subject, {
                fromProxy: true,
                setLoading: true,
              })
            }
            title={`Fetches the URL from your current Atomic-Server (${store.getServerUrl()}), instead of from the actual URL itself. Can be useful if the URL is down, but the resource is cached in your server.`}
          >
            Use proxy
          </Button>
        </Row>
      </Column>
    </ContainerWide>
  );
}

export default ErrorPage;

interface ErrorBoundaryProps {
  children: React.ReactNode;
  FallBackComponent?: React.ComponentType<{ error: Error }>;
}

interface ErrorBoundaryState {
  error?: Error;
}

export class ErrorBoundary extends React.Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  public constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { error: undefined };
  }

  public static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI.
    return { error };
  }

  public render() {
    if (this.state.error) {
      if (this.props.FallBackComponent) {
        return <this.props.FallBackComponent error={this.state.error} />;
      }

      return (
        <CrashPage
          error={this.state.error}
          clearError={() => this.setState({ error: undefined })}
          info={{} as React.ErrorInfo}
        />
      );
    }

    return this.props.children;
  }
}
