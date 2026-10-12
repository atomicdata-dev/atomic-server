/**
 * Whether the person opening an invite already has what it grants, so the
 * invite screen can step aside and open the shared resource instead.
 *
 * Checked against what this device can read, before the invite is resolved on
 * any server: the inviter's own link, or a resource already shared with them,
 * opens even where the link's origin runs no node (a browser-only workspace on
 * `app.atomic.place`).
 */

const TARGET = 'https://atomicdata.dev/properties/invite/target';
const WRITE = 'https://atomicdata.dev/properties/invite/write';
const SIGNER = 'https://atomicdata.dev/properties/signer';

export interface InviteGrant {
  target: string;
  write: boolean;
  signer?: string;
}

/** The grant a token describes, or undefined for a token that names none. */
export function readInviteGrant(token: string): InviteGrant | undefined {
  try {
    const data = JSON.parse(atob(token)) as Record<string, unknown>;
    const target = data[TARGET];

    if (typeof target !== 'string' || !target) return undefined;

    return {
      target,
      write: data[WRITE] === true,
      signer: typeof data[SIGNER] === 'string' ? data[SIGNER] : undefined,
    };
  } catch {
    return undefined;
  }
}

/** The little of a Store and a Resource this needs. */
export interface AccessResource {
  error?: unknown;
  canWrite(agent?: string): Promise<[boolean, string | undefined]>;
}

export interface AccessStore {
  getResource(subject: string): Promise<AccessResource>;
  /** Forget the cached entry for a subject, without touching its data. */
  evictResource?(subject: string): void;
}

/**
 * True when `agent` can already do what the invite grants on its target: read
 * it for a view invite, write it for an edit invite. An invite the agent signed
 * itself always counts. Gives up after `timeoutMs`, so a resource this device
 * cannot reach falls through to the normal invite screen.
 */
export async function alreadyHasInviteAccess(
  store: AccessStore,
  agent: string | undefined,
  grant: InviteGrant,
  timeoutMs = 4000,
): Promise<boolean> {
  if (!agent) return false;
  if (grant.signer === agent) return true;

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<false>(resolve => {
    timer = setTimeout(() => resolve(false), timeoutMs);
  });

  const check = (async () => {
    try {
      const resource = await store.getResource(grant.target);

      if (resource.error) {
        // The store keeps the failed read as the answer for this subject. A
        // browser invite's drive only arrives when the person joins, and a
        // cached failure would keep it from ever showing as ready.
        store.evictResource?.(grant.target);

        return false;
      }

      if (!grant.write) return true;

      return (await resource.canWrite(agent))[0];
    } catch {
      return false;
    }
  })();

  try {
    return await Promise.race([check, timeout]);
  } finally {
    clearTimeout(timer);
  }
}
