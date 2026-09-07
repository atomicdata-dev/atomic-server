import * as React from 'react';
import { useEffect, useId, useState } from 'react';
import { core, server, urls, useCurrentAgent, useStore } from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { Button } from '../components/Button';
import { Margin } from '../components/Card';
import { ContainerNarrow } from '../components/Containers';
import { editURL } from '../helpers/navigation';
import { Main } from '../components/Main';
import { Column, Row } from '../components/Row';
import { WarningBlock } from '../components/WarningBlock';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { createRoute } from '@tanstack/react-router';
import { pathNames } from './paths';
import { appRoute } from './RootRoutes';
import { saveAgentToIDB } from '@helpers/agentStorage';
import { FaCircleInfo } from 'react-icons/fa6';
import { styled } from 'styled-components';
import {
  InputStyled,
  InputWrapper,
  LabelStyled,
} from '../components/forms/InputStyles';
import { ErrorLook } from '../components/ErrorLook';
import { DrivesCard } from '../components/Drives/DrivesCard';
import { AccountRecoveryCard } from '../components/AccountRecoveryCard';
import { AgentProfileHeader } from '../components/AgentProfileHeader';
import { DeviceLockCard } from '../components/DeviceLockCard';
import { NewInstanceButton } from '../components/NewInstanceButton';
import { useSavedDrives } from '../hooks/useSavedDrives';
import { useDriveHistory } from '../hooks/useDriveHistory';
import { usePrivateDrive } from '../hooks/usePrivateDrive';
import { constructOpenURL } from '../helpers/navigation';
import { paths } from './paths';
import {
  forgetCachedRecoverySecret,
  logoutManagedSession,
} from '../helpers/managed';
import { clearHeartbeat } from '../helpers/deviceLock';

export const AgentSettingsRoute = createRoute({
  path: pathNames.agentSettings,
  component: () => <SettingsAgent />,
  getParentRoute: () => appRoute,
});

const SettingsAgent: React.FunctionComponent = () => {
  const store = useStore();
  const { agent, drive, setAgent, setDrive } = useSettings();
  // Sometimes the settings context can briefly lag behind the store on first
  // navigation. Fall back to the store-backed hook to avoid flashing the
  // logged-out panel for signed-in users.
  const [storeAgent] = useCurrentAgent();
  const effectiveAgent = agent ?? storeAgent ?? store.getAgent();
  const navigate = useNavigateWithTransition();

  const { privateDrive } = usePrivateDrive();
  const [savedDrives] = useSavedDrives();
  const [history, addToHistory, removeFromHistory] =
    useDriveHistory(savedDrives);

  // One list, with the private drive pinned to the top of it.
  //
  // It used to have a section of its own, which said "these are two kinds of
  // thing" when the honest statement is "these are your drives, and one of
  // them is special". A reader with a single other drive met two headings and
  // two cards to hold two rows.
  const myDrives = privateDrive
    ? [privateDrive, ...savedDrives.filter(subject => subject !== privateDrive)]
    : savedDrives;
  // Still kept out of Recently visited: it is not somewhere you happened to go.
  const recentDrives = history.filter(subject => subject !== privateDrive);

  const driveUrlId = useId();
  const [driveInput, setDriveInput] = useState('');
  const [driveErr, setDriveErr] = useState<Error | undefined>();
  const [showDriveUrl, setShowDriveUrl] = useState(false);

  // Signed out → there is a single canonical sign-in / onboarding surface at
  // /app/welcome (GettingStartedFlow). Redirect there rather than rendering a
  // second, parallel login form on this settings page.
  useEffect(() => {
    if (!effectiveAgent) {
      navigate({ to: paths.welcome, replace: true });
    }
  }, [effectiveAgent]);

  /**
   * Sign out, and also drop this device's cached copy of the encrypted
   * backup — so signing back in needs the full route again (email, then a
   * passkey or recovery code) rather than just a fingerprint. For shared or
   * borrowed machines.
   */
  function handleSignOutAndForget() {
    forgetCachedRecoverySecret(effectiveAgent?.subject);
    handleSignOut();
  }

  /**
   * Lock, not sign out: drops the usable agent from this device so the next
   * load needs a passkey (or the secret), while deliberately keeping the
   * control-plane session and the cached backup — it's still your machine and
   * your account, you're just closing the door behind you.
   */
  function handleLockNow() {
    clearHeartbeat();
    setAgent(undefined);
    setDrive('');
    void saveAgentToIDB(undefined);
    navigate({ to: paths.welcome, replace: true });
  }

  async function handleSignOut() {
    const currentDrive = drive;
    // Finish clearing the cookie before a subsequent sign-in can set a new one.
    // A late logout response otherwise invalidates the newly-created session.
    await logoutManagedSession();
    await saveAgentToIDB(undefined);

    // Everything that makes the UI say "signed out" happens now, synchronously.
    // `store.setAgent` drives a `useSyncExternalStore`, so the app re-renders
    // this tick; the private workspace is no longer readable, so clear the
    // active drive rather than leave it on screen; and go to the one sign-in
    // surface. This used to sit behind an `await getResource` that a public
    // drive skipped entirely, so signing out did nothing visible until a
    // refresh re-read the (now empty) agent.
    setAgent(undefined);
    // Empty, not the server origin: a drive is a workspace, and the origin is
    // the pre-DID default standing in for one. Signed out, there is no
    // workspace — say that, don't fall back to the server's own.
    setDrive('');
    navigate({ to: paths.welcome, replace: true });

    // Best-effort: if the drive we just left was private, forget it from
    // history too, so it does not reappear as a suggestion to a signed-out
    // browser. Failure here changes nothing the user can see.
    void store
      .getResource(currentDrive)
      .then(driveResource => {
        const readRight = driveResource.get(core.properties.read);
        const readArray = Array.isArray(readRight) ? readRight : [];

        if (!readArray.includes(urls.instances.publicAgent)) {
          removeFromHistory?.(currentDrive);
        }
      })
      .catch(() => undefined);
  }

  function handleSetDrive(url: string) {
    setDrive(url);
    addToHistory(url);
    navigate(constructOpenURL(url));
  }

  function handleOpenDriveInput() {
    try {
      handleSetDrive(driveInput);
    } catch (e) {
      setDriveErr(e as Error);
    }
  }

  return (
    <Main>
      <ContainerNarrow>
        {effectiveAgent ? (
          <>
            <h1>User Settings</h1>
            <Column>
              {effectiveAgent.subject?.startsWith('http://localhost') && (
                <WarningBlock>
                  <WarningBlock.Title>Warning:</WarningBlock.Title>
                  {
                    "You're using a local Agent, which cannot authenticate on other domains, because its URL does not resolve."
                  }
                </WarningBlock>
              )}
              <AgentProfileHeader subject={effectiveAgent.subject!} />
              <Row>
                <Button
                  subtle
                  onClick={() => navigate(editURL(effectiveAgent.subject!))}
                >
                  More profile fields
                </Button>
                <Button
                  subtle
                  title='Sign out. You can get back in on this device with your passkey.'
                  onClick={handleSignOut}
                  data-test='sign-out'
                >
                  Sign out
                </Button>
              </Row>

              <Margin />

              {/* Both drive actions live on the heading row, so the list
                  isn't bracketed by a card-row button above and a standalone
                  form below. The URL field stays hidden until asked for — it's
                  the rarer of the two by a wide margin. */}
              <SectionHeader>
                <Row center gap='1ch'>
                  <Heading as='h2'>My drives</Heading>
                  <InfoHint title='Your private drive is always first. Unstar any other drive to move it back to recently visited.' />
                </Row>
                <Row gap='0.5rem'>
                  <NewInstanceButton
                    klass={server.classes.drive}
                    subtle
                    icon
                    label='New'
                  />
                  <Button
                    subtle
                    // Short on screen, specific to a screen reader — and to
                    // anyone hovering, since the field it reveals is the
                    // rarer of the two actions by a wide margin.
                    aria-label='Open a drive by URL'
                    title='Open a drive by URL or DID'
                    onClick={() => setShowDriveUrl(open => !open)}
                    aria-expanded={showDriveUrl}
                    data-test='open-drive-by-url'
                  >
                    Open
                  </Button>
                </Row>
              </SectionHeader>

              {showDriveUrl && (
                <div>
                  <LabelStyled htmlFor={driveUrlId}>
                    Open a drive by URL or DID
                  </LabelStyled>
                  <Row>
                    <InputWrapper>
                      <InputStyled
                        id={driveUrlId}
                        data-testid='drive-url-input'
                        value={driveInput}
                        onChange={e => setDriveInput(e.target.value)}
                        placeholder='Enter a Drive DID or URL'
                        autoFocus
                      />
                    </InputWrapper>
                    <Button
                      onClick={handleOpenDriveInput}
                      disabled={!driveInput || drive === driveInput}
                      data-test='drive-url-save'
                    >
                      Open
                    </Button>
                  </Row>
                  {driveErr && <ErrorLook>{driveErr.message}</ErrorLook>}
                </div>
              )}

              <DrivesCard
                drives={myDrives}
                testId='my-drives'
                privateDrive={privateDrive}
                onDriveSelect={handleSetDrive}
              />

              {recentDrives.length > 0 && (
                <>
                  <Margin />
                  <Row center gap='1ch'>
                    <Heading as='h2'>Recently visited</Heading>
                    <InfoHint title='Only stored on this device. Star a drive to keep it in My drives.' />
                  </Row>
                  <DrivesCard
                    drives={recentDrives}
                    onDriveSelect={handleSetDrive}
                    onDriveRemove={removeFromHistory}
                  />
                </>
              )}

              <Margin />

              <Row center gap='1ch'>
                <Heading as='h2'>Account recovery</Heading>
                <InfoHint title='How you get back in on a new device — and where to find your agent secret.' />
              </Row>
              <AccountRecoveryCard agentSubject={effectiveAgent.subject} />

              <Margin />

              <Row center gap='1ch'>
                <Heading as='h2'>This device</Heading>
                <InfoHint title='Whether this browser stays signed in as you when anyone opens it.' />
              </Row>
              <DeviceLockCard
                agentSubject={effectiveAgent.subject}
                onLockNow={handleLockNow}
              />
              {/* Here rather than beside "Sign out", because what it does is
                  to this device: it drops the copy of the encrypted backup
                  held here. Next to an ordinary sign-out it read as a longer
                  way of saying the same thing. */}
              <Row>
                <Button
                  subtle
                  title='Sign out and remove this device’s copy of your encrypted backup'
                  onClick={handleSignOutAndForget}
                  data-test='sign-out-forget'
                >
                  Sign out &amp; forget this device
                </Button>
              </Row>
            </Column>
          </>
        ) : null}
      </ContainerNarrow>
    </Main>
  );
};

const Heading = styled.h1`
  margin: 0;
`;

/** Section title on the left, its actions on the right, one row. */
const SectionHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
`;

/** Hover-for-details icon next to a section heading, replacing hint prose. */
function InfoHint({ title }: { title: string }) {
  return (
    <InfoHintIcon title={title}>
      <FaCircleInfo aria-label={title} />
    </InfoHintIcon>
  );
}

const InfoHintIcon = styled.span`
  display: inline-flex;
  align-items: center;
  color: ${p => p.theme.colors.textLight};
  cursor: help;
  font-size: 0.9rem;
`;
