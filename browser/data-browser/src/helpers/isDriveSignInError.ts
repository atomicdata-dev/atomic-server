import {
  type Agent,
  type Resource,
  isNotAvailableLocally,
  LOCAL_ONLY_NOT_FOUND_MESSAGE,
  isUnauthorized,
} from '@tomic/react';
import { isRootWelcomeResourceError } from './isRootWelcomeResourceError';

/**
 * True when a not-signed-in visitor opened a resource they can't read that is
 * NOT the server home — e.g. a private drive opened from the managed portal on a
 * new device. This drives the drive-aware sign-in guard (welcome panel's
 * sign-in step, with the resource carried as `next` so we return there after
 * sign-in), as distinct from the server-home welcome gate
 * ({@link isRootWelcomeResourceError}).
 *
 * Gated on `!agent`: an already-signed-in atomic-server identity opens the
 * resource directly — its access is independent of any managed session.
 *
 * On an origin that runs no node (`originWithoutNode`) there is no server to
 * say "unauthorized": a drive this device does not hold fails as "not
 * available locally" instead. For a signed-out visitor that is the same
 * situation — the data can only arrive through a sign-in (a vault restore, or
 * a connected device) — so it gets the same guard. A drive opened from the
 * portal on a fresh phone is exactly this. Local-only drives require the
 * same unlock even on an origin with a node: that node does not hold them.
 */
export function isDriveSignInError(
  resource: Resource,
  agent: Agent | undefined,
  baseURL: string,
  options: { originWithoutNode?: boolean } = {},
): boolean {
  if (agent || isRootWelcomeResourceError(resource, agent, baseURL)) {
    return false;
  }

  return (
    isUnauthorized(resource.error) ||
    (isNotAvailableLocally(resource.error) &&
      (options.originWithoutNode === true ||
        resource.error?.message === LOCAL_ONLY_NOT_FOUND_MESSAGE))
  );
}
