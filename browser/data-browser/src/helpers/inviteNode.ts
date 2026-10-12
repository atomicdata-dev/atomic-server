import { isOriginWithoutNode } from './originNode';

function originOf(url: string | null | undefined): string | undefined {
  if (!url) return undefined;

  try {
    const parsed = new URL(url);

    return parsed.protocol === 'http:' || parsed.protocol === 'https:'
      ? parsed.origin
      : undefined;
  } catch {
    return undefined;
  }
}

export interface InviteNodeInput {
  /** `?server=` on the invite link. */
  serverParam?: string | null;
  /** The origin the link was opened on. */
  locationOrigin: string;
  /** The server this browser had saved before it opened the link. */
  storedServer?: string;
  /** The Vite dev server serves the app on a port with no node behind it. */
  dev?: boolean;
}

/**
 * The servers an invite link can be resolved against, best first.
 *
 * The link itself outranks whatever this browser remembered: it was built from
 * the server the drive lives on (`inviteLinkPrefix`). A saved server is
 * whatever the last session left behind, and followed blindly it sent an
 * invitee's request to `app.atomic.place`, a static host that answers every
 * path with index.html ("Unrecognized token '<'").
 */
export function inviteNodeCandidates({
  serverParam,
  locationOrigin,
  storedServer,
  dev = false,
}: InviteNodeInput): string[] {
  const ordered = [
    originOf(serverParam),
    dev ? undefined : originOf(locationOrigin),
    originOf(storedServer),
  ];

  return ordered.filter(
    (origin, i): origin is string =>
      origin !== undefined && ordered.indexOf(origin) === i,
  );
}

/** The first candidate that is not known to be an origin without a node. */
export function pickInviteNode(candidates: string[]): string | undefined {
  return candidates.find(origin => !isOriginWithoutNode(origin));
}
