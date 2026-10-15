import { useEffect, useRef, useState } from 'react';
import { decodeBrowserInvite } from '@tomic/lib';
import { useStore } from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { Button } from '../components/Button';
import { Spinner } from '../components/Spinner';
import { ContainerNarrow } from '../components/Containers';
import { Column } from '../components/Row';
import { ErrorLook } from '../components/ErrorLook';
import { getManagedPortalUrl } from '../helpers/managed/cloudSync';
import {
  automaticPeerRoom,
  requirePeerSignalingUrl,
  savePeerLink,
  resumePeerLinks,
  peerLinkStatus,
  PEER_LINK_CHANGED,
} from '../helpers/browserPeerSync';

/** How long a join may sit without a peer before the page says so. Matches
 * `WebRtcPeer`'s own pairing timeout in @tomic/lib: past this point the dialer
 * has already given up once, and peer sync reports only "Waiting for a peer"
 * either way. The attempt keeps running; this is the page admitting it. */
const PAIRING_DEADLINE = 60_000;

export function PeerInvitePage({ token }: { token: string }) {
  const store = useStore();
  const { agent, setDrive } = useSettings();
  const [status, setStatus] = useState('');
  const [ready, setReady] = useState(false);
  const [joining, setJoining] = useState(false);
  const [stalled, setStalled] = useState(false);
  const [error, setError] = useState<Error>();
  const joinedAt = useRef<number>(undefined);
  const autoJoined = useRef(false);
  const autoOpened = useRef(false);
  let invite: ReturnType<typeof decodeBrowserInvite> | undefined;

  try {
    invite = decodeBrowserInvite(token);
  } catch {
    /* Render a safe error below. */
  }

  const drive = invite?.drive;
  // The inviter opening their own link on another device: nothing to accept.
  const ownInvite = !!agent && !!invite && agent.subject === invite.issuer;
  useEffect(() => {
    const update = () => {
      const current = drive ? peerLinkStatus(drive) : '';
      const connected =
        !!drive &&
        !!store.resources.get(drive)?.isReady() &&
        current.startsWith(/* @wc-ignore */ 'Connected to');
      setStatus(current);
      setReady(connected);
      setStalled(
        !connected &&
          !!joinedAt.current &&
          Date.now() - joinedAt.current > PAIRING_DEADLINE,
      );
    };

    update();
    window.addEventListener(PEER_LINK_CHANGED, update);
    const timer = setInterval(update, 500);

    return () => {
      clearInterval(timer);
      window.removeEventListener(PEER_LINK_CHANGED, update);
    };
  }, [drive, store]);

  const join = async () => {
    try {
      const checked = decodeBrowserInvite(token);
      if (!store.getAgent() || !store.getClientDb())
        throw new Error('Sign in and wait for local storage to be ready.');
      // Only a newly received drive is made local-only. Existing server placement
      // belongs to its explicit hosting flow, not to invitation routing.
      if (
        !(await store.getClientDb()!.getResourceWithSnapshot(checked.drive))
          .snapshot
      )
        store.registerLocalOnlyDrive(checked.drive);
      savePeerLink(store, {
        drive: checked.drive,
        room: await automaticPeerRoom(checked.drive),
        signalingUrl: requirePeerSignalingUrl(),
        expectedPeer: checked.issuer,
        invitation: token,
      });
      resumePeerLinks(store);
      joinedAt.current = Date.now();
      setJoining(true);
      setStalled(false);
      setError(undefined);
    } catch (e) {
      setError(
        e instanceof Error ? e : new Error('Could not join this drive.'),
      );
    }
  };

  const open = () => {
    if (!drive) return;
    setDrive(drive);
    window.location.assign(
      `/app/show?${new URLSearchParams({ subject: drive })}`,
    );
  };

  useEffect(() => {
    if (!ownInvite || autoJoined.current) return;

    const tryJoin = () => {
      if (autoJoined.current || !store.getAgent() || !store.getClientDb())
        return;
      autoJoined.current = true;
      clearInterval(timer);
      void join();
    };

    const timer = setInterval(tryJoin, 500);

    tryJoin();

    return () => clearInterval(timer);
    // `join` only reads the token and the store.
    // oxlint-disable-next-line react-hooks/exhaustive-deps
  }, [ownInvite, store, token]);

  useEffect(() => {
    if (!ownInvite || !ready || autoOpened.current) return;
    autoOpened.current = true;
    open();
    // oxlint-disable-next-line react-hooks/exhaustive-deps
  }, [ownInvite, ready]);

  const signIn = () => {
    const portal = getManagedPortalUrl();
    const url = portal
      ? new URL('/signin', portal)
      : new URL('/app/welcome', window.location.origin);
    url.searchParams.set('invite', token);
    window.location.assign(url.href);
  };

  return (
    <ContainerNarrow>
      <Column>
        <h1>
          {invite
            ? invite.write
              ? "You're invited to edit this drive"
              : "You're invited to view this drive"
            : 'Invitation unavailable'}
        </h1>
        {invite ? (
          <>
            <p>
              This drive syncs between browsers. The person who invited you
              needs to keep their browser open while you join.
            </p>
            {!agent ? (
              <Button onClick={signIn}>Sign in to join</Button>
            ) : ready ? (
              <Button onClick={open}>Open drive</Button>
            ) : ownInvite ? (
              !error && <Spinner centered />
            ) : (
              <Button onClick={join} disabled={joining}>
                {joining ? 'Connecting…' : 'Join drive'}
              </Button>
            )}
            {joining && (
              <p role='status'>
                {stalled
                  ? 'This is taking longer than it should. The person who invited you needs to have this drive open in their browser. Try again, or ask them for a new invitation.'
                  : status || 'Looking for the inviter’s browser…'}
              </p>
            )}
            {joining && !ready && (
              <Button subtle onClick={join}>
                Retry
              </Button>
            )}
          </>
        ) : (
          <p>
            This invitation is invalid or has expired. Ask for a new invitation.
          </p>
        )}
        {error && <ErrorLook>{error.message}</ErrorLook>}
      </Column>
    </ContainerNarrow>
  );
}
