import { DiscoverWorkspace } from './DiscoverWorkspace';
import React, { useEffect, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaMobileScreenButton, FaLock } from 'react-icons/fa6';
import { useStore } from '@tomic/react';
import { useDriveVault } from '../../helpers/managed/useDriveVault';
import { listVaultDrives } from '../../helpers/managed/vault';
import { getManagedAccount } from '../../helpers/managed/session';
import { canHoldProviderCookie } from '../../helpers/managed/deviceLink';
import { safePortalUrl } from '../../helpers/managed/api';
import { openExternal } from '../../helpers/openExternal';
import { PRODUCT_NAME } from '../../helpers/managed/product';
import { LinkProviderPanel } from '../../components/Vault/LinkProviderPanel';
import { Button } from '../../components/Button';
import { Column, Row } from '../../components/Row';
import { PairingCode } from '../../components/PairingCode';
import { ConnectToDeviceForm } from '../../components/ConnectToDeviceForm';
import { InputStyled, InputWrapper } from '../../components/forms/InputStyles';
import { useOwnNodeDid } from '../../hooks/useOwnNodeDid';
import {
  usePairingFlow,
  type WorkspaceResult,
} from '../../components/pairing/PairingFlowProvider';
import { useSettings } from '../../helpers/AppSettings';
import { deviceHasDriveData } from '../../helpers/driveData';
import { fetchPrivateDriveSubject } from '../../helpers/privateDrive';
import { fetchManagedInfo } from '../../helpers/managedServer';
import { normalizeServerUrl, serverLabel } from '../../helpers/serverUrl';
import { isRunningInTauri } from '../../helpers/tauri';
import {
  CardSubtitle,
  CardTitle,
  OnboardingCard,
  OnboardingWrap,
  FooterBar,
} from './chrome';

/**
 * `/iroh-sync` answers as soon as the peer's push is imported, which is not the
 * same moment the drive becomes fetchable — and a paired peer may also deliver
 * it a beat later over the live connection. Checking once raced that and told
 * people their workspace wasn't there while it was landing.
 *
 * So poll, and poll long enough that giving up means something. The dialog
 * shows a spinner throughout, and a stated reason after.
 */
const DRIVE_WAIT_MS = 30_000;
const DRIVE_POLL_INTERVAL_MS = 1_000;

/** How often to look while a code is on screen, waiting for a scan to push. */
const WATCH_INTERVAL_MS = 3_000;

interface ConnectDeviceStepProps {
  /** The drive that should be here but isn't. Absent if none resolved. */
  drive?: string;
  /**
   * Why sign-in's own vault restore of `drive` came back empty-handed, in the
   * vault's words ("drive is not backed up", "the vault is empty", …). Shown
   * when there is nothing to restore, so the screen says which of the several
   * "no backup" situations this is instead of a generic shrug.
   */
  vaultReason?: string;
  /**
   * The control plane that keeps this account's backups, if the build or a
   * server has named one. Without it there is no vault to ask and no account
   * to sign in to, so the restore offer stays off the screen.
   */
  portalUrl: string | null;
  /** Enter the app anyway, without its data. */
  onSkip: () => void;
  /** The drive's data arrived — open it. */
  onConnected: (drive: string) => void;
}

/**
 * Shown right after signing in on a device that holds none of the account's
 * data. A secret restores *who you are*, not *what you have*: the workspace
 * still lives on whichever device made it, and the only way across is to reach
 * that device.
 *
 * Both directions of the QR work, because a peer sync reconciles both ways:
 * scan the other device's code from here (phones have the camera), or let the
 * other device scan the code shown here (desktops don't). Either way this
 * device ends up holding the drive.
 *
 * A plain browser tab has no node of its own, so it shows the code of the
 * always-on device it reads from: scanning that from the device holding the
 * workspace syncs it there, and this reads it from there. Same code, same
 * component, as the Sync page — a person who has seen one has seen both.
 */
export function ConnectDeviceStep({
  drive,
  vaultReason,
  portalUrl,
  onSkip,
  onConnected,
}: ConnectDeviceStepProps): JSX.Element {
  const store = useStore();
  const { agent, baseURL, setServer } = useSettings();
  const nodeDid = useOwnNodeDid();
  const isNode = isRunningInTauri();
  const startPairing = usePairingFlow();
  const [serverInput, setServerInput] = useState('');
  /**
   * The node another device should reach to put the workspace within this
   * browser's reach. A browser is not a node, so it shows the code of the
   * always-on device it reads from: scanning that syncs the workspace there,
   * and this reads it from there. Same code the Sync page shows.
   */
  const [reachableNodeDid, setReachableNodeDid] = useState<string>();

  /**
   * The drive we should open. Re-resolved rather than trusted: on a device that
   * held nothing, the agent's personal drive may only become knowable once the
   * agent resource itself has been pulled across.
   */
  async function resolveDriveSubject(): Promise<string | undefined> {
    return (
      drive ??
      (agent
        ? await fetchPrivateDriveSubject(store, agent).catch(() => undefined)
        : undefined)
    );
  }

  /**
   * The same subject, in state, because asking the vault about a drive needs a
   * value during render rather than a promise.
   */
  const [vaultDrive, setVaultDrive] = useState<string | undefined>(drive);

  /**
   * Whether this client holds a session with the control plane; `undefined`
   * until asked. The vault is behind that session, so without one the screen
   * below cannot see the backup this device most likely came here for — and
   * the sign-in that just happened does not create one. A passkey or secret
   * proves the agent; the account is a separate login, and a browser that has
   * never visited the portal (or cleared its cookies) has none. That case used
   * to render as "your data is on another device" with no way to fix it.
   */
  const [hasSession, setHasSession] = useState<boolean>();

  /**
   * Bumped once the user has signed in or linked, so the vault lookup below
   * runs again without leaving the step.
   */
  const [sessionAttempt, setSessionAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      const local = await resolveDriveSubject();

      if (cancelled) return;

      if (local) setVaultDrive(local);

      const account = await getManagedAccount().catch(() => null);

      if (cancelled) return;

      setHasSession(account !== null);

      // Nothing below can answer without a session; asking would only fail.
      if (account === null) return;

      // The control plane knows which drives this account has backed up, and
      // asking it matters in two cases. With no drive name at all: a device
      // holding nothing may have no server to derive one from — the desktop
      // and Android apps embed their own, empty one — and without this the
      // restore offer never appears on exactly the device that needs it. With
      // a name: the key-derived drive is only the *default* home. An account
      // whose data lives in another drive (made before the derived scheme, or
      // made by hand) has that one backed up and the derived one enrolled but
      // empty, and asking about the empty one says "nothing to restore" while
      // the backup sits one entry over.
      try {
        const enrolled = await listVaultDrives();

        if (cancelled) return;

        const mine = enrolled.filter(
          e =>
            e.status === 'active' &&
            (!agent || !e.agent_subject || e.agent_subject === agent.subject),
        );
        const named = local
          ? mine.find(e => e.drive_subject === local)
          : undefined;

        if (named?.last_backup_at) return;

        const backed = mine
          .filter(e => e.last_backup_at)
          .sort((a, b) => b.last_backup_at! - a.last_backup_at!)[0];

        if (backed) setVaultDrive(backed.drive_subject);
        else if (!local && mine[0]) setVaultDrive(mine[0].drive_subject);
      } catch {
        // No session, or no control plane at all. Nothing to offer, which the
        // panel renders as nothing rather than as an error.
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [drive, agent?.subject, sessionAttempt]);

  const vault = useDriveVault(vaultDrive ?? null);
  // Only offer this when there is something to restore. Backup being on with
  // nothing stored yet is a dead end, and an empty vault would return zero
  // resources and leave the screen looking like it failed.
  const canRestoreFromVault =
    vault.status.state === 'on' && vault.status.details.confirmed_objects > 0;

  /**
   * The account session appeared (signed in on the portal in another tab, or
   * linked this device). Ask the control plane again, from here: the vault
   * lookup above and the hook's own status both answered "no session" and
   * nothing they watch changes when a cookie or a token does.
   */
  function sessionArrived() {
    setSessionAttempt(n => n + 1);
    void vault.refresh();
  }

  // Offered when the vault cannot be consulted for want of a session, and only
  // when there is somewhere to get one. Not shown once the session is there
  // and the vault simply has nothing — that is what `vaultReason` is for.
  const needsSession = hasSession === false && !!portalUrl;

  async function restoreFromVault() {
    const outcome = await vault.restore();

    // `restore` reports its own failure through `vault.error`, which is
    // rendered below; there is nothing to navigate to if it did not work.
    if (outcome && vaultDrive) onConnected(vaultDrive);
  }

  /** One look — for the "did connecting a server fix this?" check below. */
  async function driveIsHere(): Promise<string | undefined> {
    const candidate = await resolveDriveSubject();

    if (!candidate) {
      return undefined;
    }

    return (await deviceHasDriveData(store, candidate, { refresh: true }))
      ? candidate
      : undefined;
  }

  /** Wait for the drive to land, and say why when it doesn't. */
  async function awaitWorkspace(): Promise<WorkspaceResult> {
    const candidate = await resolveDriveSubject();

    if (!candidate) {
      return { ok: false, reason: 'unknown-drive' };
    }

    const deadline = Date.now() + DRIVE_WAIT_MS;

    for (;;) {
      // The store cached a failed fetch of this drive a moment ago (that's how
      // we got here); ask the server again now that the sync has filled it in.
      if (await deviceHasDriveData(store, candidate, { refresh: true })) {
        return { ok: true, drive: candidate };
      }

      if (Date.now() >= deadline) {
        return { ok: false, reason: 'timeout' };
      }

      await new Promise(resolve => setTimeout(resolve, DRIVE_POLL_INTERVAL_MS));
    }
  }

  // Connecting a server is the browser's route out of here, and it can put the
  // drive back in reach. Notice that, rather than leaving the user on a screen
  // whose problem they just solved.
  useEffect(() => {
    if (isNode) {
      return;
    }

    let cancelled = false;

    void driveIsHere().then(arrived => {
      if (!cancelled && arrived) {
        onConnected(arrived);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [baseURL]);

  useEffect(() => {
    if (isNode || !baseURL) return;

    let cancelled = false;

    void fetchManagedInfo(baseURL).then(info => {
      if (!cancelled && info.nodeId) setReachableNodeDid(info.nodeId);
    });

    return () => {
      cancelled = true;
    };
  }, [baseURL, isNode]);

  // A scan pushes from the other device, which changes nothing here to react
  // to — so watch. Without this the workspace lands and the screen sits there,
  // still asking for it.
  useEffect(() => {
    if (isNode || !reachableNodeDid) return;

    let cancelled = false;

    const timer = setInterval(async () => {
      const arrived = await driveIsHere();

      if (!cancelled && arrived) {
        clearInterval(timer);
        onConnected(arrived);
      }
    }, WATCH_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [reachableNodeDid, isNode]);

  function connectWithCode(code: string) {
    // The dialog owns the progress and the outcome from here: connect, then
    // wait for the workspace to actually land, then offer to open it.
    startPairing(code, {
      drive,
      awaitWorkspace,
      onWorkspaceReady: onConnected,
    });
  }

  const otherDeviceRoutes = isNode ? (
    <>
      <Section>
        <SectionTitle>Connect to that device</SectionTitle>
        <Explainer>
          Open <strong>Sync</strong> there and scan or paste its code here.
        </Explainer>
        <ConnectToDeviceForm onCode={connectWithCode} />
      </Section>

      {nodeDid && (
        <Section>
          <SectionTitle>…or let it scan this one</SectionTitle>
          <QrRow>
            <PairingCode nodeDid={nodeDid} />
          </QrRow>
        </Section>
      )}
    </>
  ) : (
    <>
      {reachableNodeDid && (
        <Section>
          <SectionTitle>Scan this from that device</SectionTitle>
          <Explainer>
            It syncs your workspace to {serverLabel(baseURL)}, which this
            browser reads from.
          </Explainer>
          <QrRow>
            <PairingCode nodeDid={reachableNodeDid} />
          </QrRow>
        </Section>
      )}

      <Section>
        <SectionTitle>
          {reachableNodeDid
            ? '…or read it from a server'
            : 'Connect a server that has it'}
        </SectionTitle>
        <form
          onSubmit={(e: React.FormEvent) => {
            e.preventDefault();

            const url = normalizeServerUrl(serverInput);

            if (url) setServer(url);
          }}
        >
          <Row gap='0.5rem'>
            <InputWrapper>
              <InputStyled
                autoComplete='off'
                placeholder='localhost:9883 or your-server.example'
                value={serverInput}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setServerInput(e.target.value)
                }
              />
            </InputWrapper>
            <Button type='submit' subtle disabled={!serverInput.trim()}>
              Connect
            </Button>
          </Row>
        </form>
      </Section>
    </>
  );

  // One thing at a time. The screen names a single way in — the backup when
  // it is in reach, the account sign-in that puts it in reach, and only
  // failing both the second-device routes. Whatever is not the one way in
  // folds away below it: still there, no longer competing.
  //
  // `restore` is the only route that needs nothing but this device; the
  // others want a second device that is switched on and reachable, which for
  // someone restoring after losing one may not exist. `session` is the case
  // this screen used to render as "your data is on another device" with no
  // way to fix it: the backup is behind the account, and signing in as the
  // agent did not sign in to the account.
  const primary: 'restore' | 'session' | 'none' = canRestoreFromVault
    ? 'restore'
    : needsSession
      ? 'session'
      : 'none';

  const title = {
    restore: 'Restore your workspace',
    session: 'Bring your data back',
    none: 'Your data is on another device',
  }[primary];

  // The default line says the data stays where it was made, which is exactly
  // wrong for someone with an encrypted backup: theirs is in the vault,
  // sealed, and restorable right here. Telling them otherwise sends them
  // hunting for a device they may no longer have.
  const subtitle = {
    restore: 'There’s an encrypted backup, sealed so only you can open it.',
    session: `Your backup is kept by your ${PRODUCT_NAME} account. Sign in to it and it comes back here.`,
    none: 'Signing in restores who you are. Your workspace still lives on the device you made it with.',
  }[primary];

  return (
    <OnboardingWrap>
      <OnboardingCard>
        <Column gap='1rem'>
          <Badge>
            {primary === 'none' ? (
              <FaMobileScreenButton aria-hidden />
            ) : (
              <FaLock aria-hidden />
            )}
          </Badge>
          <CardTitle>
            {isNode && drive ? 'Find your workspace' : title}
          </CardTitle>
          {!(isNode && drive) && <CardSubtitle>{subtitle}</CardSubtitle>}
          {isNode && drive && (
            <DiscoverWorkspace drive={drive} onConnected={onConnected} />
          )}

          {/* The vault's own account of why there is nothing to restore. Five
              situations answer "no backup" — never enrolled, enrolled but
              never uploaded, … — and they want different fixes on the other
              device, so name it. */}
          {primary === 'none' && vaultReason && (
            <Explainer data-testid='vault-no-backup-reason'>
              Cloud Vault had nothing for this workspace: {vaultReason}.
            </Explainer>
          )}

          {/* Two ways to get a session, one per client (see the restore
              step): a page on the portal's site signs in there and keeps the
              cookie; the apps and a self-hosted origin cannot, and link this
              device instead. */}
          {primary === 'session' && (
            <VaultOffer data-testid='vault-needs-session'>
              {canHoldProviderCookie(portalUrl) ? (
                <>
                  <Button
                    type='button'
                    data-testid='vault-sign-in'
                    onClick={() => {
                      // A new tab, not a redirect: the sign-in is a magic
                      // link that lands on the portal, and this screen is
                      // where the restore happens. Leaving it means finding
                      // the way back through Sync.
                      const portal = safePortalUrl(portalUrl);

                      if (portal) {
                        void openExternal(
                          new URL('/signin', portal).toString(),
                        );
                      }
                    }}
                  >
                    {`Sign in to ${PRODUCT_NAME}`}
                  </Button>
                  <TextButton type='button' onClick={sessionArrived}>
                    I’ve signed in — check again
                  </TextButton>
                </>
              ) : (
                <LinkProviderPanel
                  compact
                  portalUrl={portalUrl}
                  onLinked={sessionArrived}
                />
              )}
            </VaultOffer>
          )}

          {primary === 'restore' && (
            <VaultOffer data-testid='vault-restore-offer'>
              {vault.error && <ErrorText role='alert'>{vault.error}</ErrorText>}
              {vault.restoreProgress !== null && (
                <Explainer>
                  Restoring… {Math.round(vault.restoreProgress * 100)}%
                </Explainer>
              )}
              <Button
                type='button'
                data-testid='vault-restore-now'
                onClick={restoreFromVault}
                disabled={vault.busy}
              >
                {vault.busy ? 'Restoring…' : 'Restore my workspace'}
              </Button>
            </VaultOffer>
          )}

          {primary === 'none' ? (
            otherDeviceRoutes
          ) : (
            /* Demoted, not removed: still the answer for a workspace that was
               never backed up, or whose latest changes were made elsewhere. */
            <OtherRoutes>
              <OtherRoutesSummary>
                …or bring it over from another device
              </OtherRoutesSummary>
              {otherDeviceRoutes}
            </OtherRoutes>
          )}
        </Column>
      </OnboardingCard>

      <FooterBar>
        <Button subtle type='button' onClick={onSkip}>
          Skip for now
        </Button>
      </FooterBar>
    </OnboardingWrap>
  );
}

const Badge = styled.div`
  align-self: center;
  width: 3rem;
  height: 3rem;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.3rem;
  color: ${p => p.theme.colors.main};
  background: ${p => p.theme.colors.main}1c;
`;

const Section = styled.section`
  display: flex;
  flex-direction: column;
`;

const SectionTitle = styled.h3`
  font-size: 1rem;
  margin: 0 0 0.3rem;
`;

const Explainer = styled.p`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;
  margin: 0 0 0.6rem;
`;

/** Centred, to sit under the card's centred title rather than beside it. */
const VaultOffer = styled.section`
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.6rem;
  text-align: center;
  padding: 0.5rem 0 0.25rem;
`;

/** A secondary action that should not compete with the one above it. */
const TextButton = styled.button`
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;
  text-decoration: underline;

  &:hover {
    color: ${p => p.theme.colors.text};
  }
`;

const ErrorText = styled.p`
  color: ${p => p.theme.colors.alert};
  font-size: 0.85rem;
  margin: 0 0 0.6rem;
`;

/**
 * The second-device routes, folded away when a vault restore is on offer.
 *
 * A `details` rather than state: it needs no JS, keyboard and screen-reader
 * behaviour come for free, and the content stays in the DOM so nothing about
 * it is actually hidden from someone looking for it.
 */
const OtherRoutes = styled.details`
  display: flex;
  flex-direction: column;
`;

const OtherRoutesSummary = styled.summary`
  cursor: pointer;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;
  text-align: center;
  padding: 0.4rem 0;
  margin-bottom: 0.4rem;

  &:hover {
    color: ${p => p.theme.colors.text};
  }
`;

const QrRow = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  min-width: 0;
`;
