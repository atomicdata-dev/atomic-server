import { useStore, useCurrentAgent, server, type Resource } from '@tomic/react';
import { generateInviteToken } from '@tomic/lib';
import { prepareDriveSharing } from '../../helpers/managed/prepareDriveSharing';
import { managedFetch } from '../../helpers/managed/api';
import {
  automaticPeerRoom,
  requirePeerSignalingUrl,
  savePeerLink,
  resumePeerLinks,
} from '../../helpers/browserPeerSync';
import { getManagedPortalUrl } from '../../helpers/managed/cloudSync';
import { isOriginWithoutNode } from '../../helpers/originNode';

export interface InviteLinkOptions {
  write: boolean;
  /** Unix ms timestamp after which the invite no longer works */
  expiresAt?: number;
  /** How many people may use the link. The server enforces it. */
  maxUsages?: number;
}

/**
 * Returns a function that signs an invite token for `target` and builds the
 * `/app/invite` URL for it. Shared by the Share dialog (link and email
 * invites).
 */
export function useCreateInviteLink(
  target: Resource,
): (options: InviteLinkOptions) => Promise<string> {
  const store = useStore();
  const [agent] = useCurrentAgent();
  const isSaas = !!getManagedPortalUrl();

  return async ({ write, expiresAt, maxUsages }) => {
    if (!agent) {
      throw new Error('No agent found');
    }

    const isDrive = target.hasClasses(server.classes.drive);
    let browserPeer = isDrive && store.isLocalOnlyDrive(target.subject);

    if (isDrive && isSaas && !browserPeer) {
      const response = await managedFetch('/sync-enrollments', {});

      if (!response.ok || response.status === 204)
        throw new Error(
          'Sign in to your portal account to check this drive before sharing.',
        );
      const body = await response.json();
      const enrollments = Array.isArray(body) ? body : body.enrollments;

      if (!Array.isArray(enrollments))
        throw new Error('Could not check Cloud Server status. Try again.');
      browserPeer = await prepareDriveSharing(
        store,
        target.subject,
        enrollments,
      );
    }

    if (
      browserPeer &&
      !(await store.getClientDb()?.getResourceWithSnapshot(target.subject))
        ?.snapshot
    )
      throw new Error(
        'Wait for this drive to be saved on this device before sharing.',
      );
    const signalingUrl = browserPeer ? requirePeerSignalingUrl() : undefined;
    const tokenBase64 = await generateInviteToken(
      target.subject,
      agent,
      write,
      expiresAt,
      undefined,
      browserPeer,
      maxUsages,
    );

    if (browserPeer) {
      savePeerLink(store, {
        drive: target.subject,
        room: await automaticPeerRoom(target.subject),
        signalingUrl: signalingUrl!,
      });
      resumePeerLinks(store);
    }

    const serverUrl = store.getServerUrl();

    if (browserPeer) {
      return `${window.location.origin}/app/invite?token=${encodeURIComponent(tokenBase64)}`;
    }

    // A link to a host that runs no node opens a page that cannot find the
    // invite. Better to say so now than to hand over a link that never works.
    if (isOriginWithoutNode(serverUrl)) {
      throw new Error(
        'This drive is not on a server this app can reach, so it cannot be shared with a link yet. Open it from its own server and try again.',
      );
    }

    return `${inviteLinkPrefix(serverUrl)}${encodeURIComponent(tokenBase64)}${inviteLinkSuffix(serverUrl)}`;
  };
}

/**
 * Whether the app is served by a different origin than the server it talks to:
 * only the Vite dev server, which serves the app on its own port. There the
 * server has no frontend of its own, so a link to it lands on a page that
 * cannot load.
 */
function servedByDevServer(serverUrl: string): boolean {
  return (
    import.meta.env.DEV &&
    new URL(serverUrl, window.location.origin).origin !== window.location.origin
  );
}

/** Where invite links for this store point, before one has been made. */
export function inviteLinkPrefix(serverUrl: string): string {
  const base = servedByDevServer(serverUrl)
    ? window.location.origin
    : serverUrl.replace(/\/$/, '');

  return `${base}/app/invite?token=`;
}

/**
 * The server to open the link against, when the link points at the app rather
 * than the server: a browser that has another server saved from earlier
 * (`localhost:9883` from another checkout) would otherwise use that one.
 */
function inviteLinkSuffix(serverUrl: string): string {
  return servedByDevServer(serverUrl)
    ? `&server=${encodeURIComponent(new URL(serverUrl).origin)}`
    : '';
}
