import * as React from 'react';
import {
  NOT_AVAILABLE_LOCALLY_MESSAGE,
  NOT_AVAILABLE_SERVER_UNREACHABLE_MESSAGE,
  isNotAvailableLocally,
  isUnauthorized,
  useStore,
} from '@tomic/react';
import { useLocation, useNavigate } from '@tanstack/react-router';
import { ContainerWide } from '../components/Containers';
import { ErrorBlock } from '../components/ErrorLook';
import { Button } from '../components/Button';
import { useSettings } from '../helpers/AppSettings';
import { ResourcePageProps } from './ResourcePage';
import { Column, Row } from '../components/Row';
import CrashPage from './CrashPage';
import { AtomicLink } from '../components/AtomicLink';
import { paths } from '../routes/paths';
import { isRootWelcomeResourceError } from '../helpers/isRootWelcomeResourceError';
import { isDriveSignInError } from '../helpers/isDriveSignInError';
import { isOriginWithoutNode } from '../helpers/originNode';
import { RootWelcomeGate } from './RootWelcomeGate';
import { VaultRestoreAction } from '../components/Vault/VaultRestoreAction';
import { constructOpenURL } from '../helpers/navigation';
import { DriveUnavailable } from './DriveUnavailable';
import { usePrivateDrive } from '../hooks/usePrivateDrive';
import { isPrivateDrive } from '../helpers/isPrivateDrive';

import type { JSX } from 'react';

/**
 * A View for Resource Errors. Not to be confused with the CrashPage, which is
 * for App wide errors.
 */
function ErrorPage({ resource }: ResourcePageProps): JSX.Element {
  const { agent, baseURL, drive } = useSettings();
  const store = useStore();
  const { privateDrive, loading: privateDriveLoading } = usePrivateDrive();
  const navigate = useNavigate();
  const location = useLocation();

  const isHomeWelcome = isRootWelcomeResourceError(resource, agent, baseURL);
  // Not signed in + can't read this (non-home) resource → send to the welcome
  // panel's sign-in step, carrying the resource as `next` so we return the user
  // here once they sign in. (Already signed in? No redirect — that agent just
  // lacks access, handled below.)
  const isDriveSignIn = isDriveSignInError(resource, agent, baseURL, {
    originWithoutNode: isOriginWithoutNode(store.getServerUrl()),
  });
  const shouldGoToWelcome = (!agent && isHomeWelcome) || isDriveSignIn;

  React.useEffect(() => {
    if (!shouldGoToWelcome) return;
    if (location.pathname === paths.welcome) return;

    navigate({
      to: paths.welcome,
      search: {
        next: isDriveSignIn ? resource.subject : undefined,
        from_portal: undefined,
      },
      replace: true,
    });
  }, [
    location.pathname,
    navigate,
    shouldGoToWelcome,
    isDriveSignIn,
    resource.subject,
  ]);

  if (
    shouldGoToWelcome ||
    isRootWelcomeResourceError(resource, agent, baseURL)
  ) {
    // Redirect effect above will handle the URL; render something safe meanwhile.
    return <RootWelcomeGate subject={baseURL || resource.subject} />;
  }

  if (isUnauthorized(resource.error)) {
    if (!agent) {
      // Redirect effect above will handle the URL.
      return <RootWelcomeGate subject={baseURL || resource.subject} />;
    }

    return (
      <ContainerWide>
        <Column>
          <h1>This account does not have access</h1>
          <p>
            You’re signed in, but this account cannot read this resource. Open
            it with the account that owns it, or ask its owner to share it with
            you.
          </p>
          <Row wrapItems>
            <Button
              onClick={() =>
                navigate({
                  to: paths.welcome,
                  search: { next: resource.subject, from_portal: undefined },
                })
              }
            >
              Use another account
            </Button>
            <Button
              subtle
              onClick={() => store.fetchResourceFromServer(resource.subject)}
            >
              Retry
            </Button>
          </Row>
        </Column>
      </ContainerWide>
    );
  }

  // Deleted on this device: going back in history after leaving a demo or a
  // template preview lands here, since leaving deletes it. Retrying cannot
  // bring it back, so offer the way forward instead of a raw error.
  if (store.isDestroyed(resource.subject)) {
    const home = drive && drive !== resource.subject ? drive : undefined;

    return (
      <ContainerWide>
        <Column>
          <h1>This page no longer exists</h1>
          <p>It was deleted, for example when you left a demo or a preview.</p>
          <Row>
            {home && (
              <Button onClick={() => navigate({ to: constructOpenURL(home) })}>
                Open your drive
              </Button>
            )}
            <Button
              subtle={!!home}
              onClick={() => navigate({ to: paths.newDrive })}
            >
              Choose a template
            </Button>
          </Row>
        </Column>
      </ContainerWide>
    );
  }

  // No copy here and nothing to fetch it from right now: an explanation that
  // keeps retrying, not a raw transport error. Only for a whole drive this
  // device lacks, or when there is no server at all: an item missing from a
  // local-only drive this device does hold was more likely deleted. The open
  // drive counts as a drive even before this device registered it.
  if (
    isNotAvailableLocally(resource.error) &&
    (resource.error!.message === NOT_AVAILABLE_LOCALLY_MESSAGE ||
      resource.error!.message === NOT_AVAILABLE_SERVER_UNREACHABLE_MESSAGE ||
      store.isLocalOnlyDrive(resource.subject) ||
      store.normalizeSubject(resource.subject) ===
        (drive && store.normalizeSubject(drive)))
  ) {
    // The private drive and what is in it is the person's own vault: never
    // "not on this device", whichever item is open.
    const vault =
      isPrivateDrive(drive, privateDrive, privateDriveLoading) ||
      isPrivateDrive(resource.subject, privateDrive, privateDriveLoading);

    return (
      <DriveUnavailable
        subject={resource.subject}
        error={resource.error!}
        vault={vault}
      />
    );
  }

  return (
    <ContainerWide>
      <Column>
        <h1>Could not open {resource.subject}</h1>
        <ErrorBlock error={resource.error!} />
        {/* A drive this device never held may be in the account's vault. */}
        {agent && <VaultRestoreAction subject={resource.subject} />}
        {resource.subject === baseURL && (
          <p>
            If you have not set up an identity on this server yet,{' '}
            <AtomicLink path={paths.onboarding}>create one here</AtomicLink>.
          </p>
        )}
        <Row>
          <Button
            onClick={() =>
              store.fetchResourceFromServer(resource.subject, {
                setLoading: true,
              })
            }
          >
            Retry
          </Button>
          {/* <Button
            title='Clear all local data & refresh page'
            onClick={clearAllLocalData}
          >
            Hard reset
          </Button> */}
          <Button
            onClick={() =>
              store.fetchResourceFromServer(resource.subject, {
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

  public static getDerivedStateFromError(error: Error) {
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
