import { useEffect, useState } from 'react';
import { decodeBrowserInvite } from '@tomic/lib';
import { useStore } from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { Button } from '../components/Button';
import { ContainerNarrow } from '../components/Containers';
import { Column } from '../components/Row';
import { ErrorLook } from '../components/ErrorLook';
import { getManagedPortalUrl } from '../helpers/managed/cloudSync';
import {
  automaticPeerRoom,
  defaultPeerSignalingUrl,
  savePeerLink,
  resumePeerLinks,
  peerLinkStatus,
  PEER_LINK_CHANGED,
} from '../helpers/browserPeerSync';

export function PeerInvitePage({ token }: { token: string }) {
  const store = useStore();
  const { agent, setDrive } = useSettings();
  const [status, setStatus] = useState('');
  const [ready, setReady] = useState(false);
  const [joining, setJoining] = useState(false);
  const [error, setError] = useState<Error>();
  let invite: ReturnType<typeof decodeBrowserInvite> | undefined;

  try {
    invite = decodeBrowserInvite(token);
  } catch {
    /* Render a safe error below. */
  }

  const drive = invite?.drive;
  useEffect(() => {
    const update = () => {
      const current = drive ? peerLinkStatus(drive) : '';
      setStatus(current);
      setReady(
        !!drive &&
          !!store.resources.get(drive)?.isReady() &&
          current.startsWith(/* @wc-ignore */ 'Connected to'),
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
        signalingUrl: defaultPeerSignalingUrl(),
        expectedPeer: checked.issuer,
        invitation: token,
      });
      resumePeerLinks(store);
      setJoining(true);
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

  const signIn = () => {
    const portal = getManagedPortalUrl();
    const url = new URL(portal ?? '/app/welcome', window.location.origin);
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
            ) : (
              <Button onClick={join} disabled={joining}>
                {joining ? 'Connecting…' : 'Join drive'}
              </Button>
            )}
            {joining && (
              <p role='status'>
                {status || 'Looking for the inviter’s browser…'}
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
