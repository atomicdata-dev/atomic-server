import { getRememberedManagedPortalUrl, safePortalUrl } from './api';
import {
  enableCloudSyncForDrive,
  ensureManagedSession,
  getManagedPortalUrl,
} from './cloudSync';
import type { ManagedInfo } from '../managedServer';

/**
 * Whether to offer "Host on atomic.place" for a drive, from facts the caller
 * already has. Pure, so each reason to stay quiet is a test.
 *
 * The offer is for someone whose drive is not hosted anywhere yet. It stays
 * away when
 *  - no portal is known (a source build names none; the open core never
 *    assumes one),
 *  - the person picked their own server, which is a decision, not a gap,
 *  - the server in use is a managed node, so the drive is already hosted,
 *  - or the account already has an enrollment for it.
 */
export function shouldOfferPortalHosting(input: {
  portalUrl: string | null;
  serverExplicitlyChosen: boolean;
  serverManaged: boolean;
  enrolled: boolean;
}): boolean {
  return (
    !!input.portalUrl &&
    !input.serverExplicitlyChosen &&
    !input.serverManaged &&
    !input.enrolled
  );
}

/** Any portal this build or install knows of, through the existing helpers. */
export function knownPortalUrl(info?: ManagedInfo | null): string | null {
  return (
    safePortalUrl(
      getManagedPortalUrl(info) ?? getRememberedManagedPortalUrl(),
    ) ?? null
  );
}

export type HostOnPortalOutcome =
  | { status: 'hosted'; httpOrigin: string; replicated: boolean }
  | { status: 'no-portal' }
  | { status: 'cancelled' };

type HostArgs = Parameters<typeof enableCloudSyncForDrive>[0];

/**
 * Host `drive` on the account service: the same enrollment the Sync page's
 * Cloud Server row runs, started from somewhere else.
 *
 * Without a session this opens the portal's own sign-in (email and magic
 * link), shares its cookie jar, and retries once the person is signed in.
 * The caller has already shown the hosting consent; it is passed through as
 * `hostingConsentAccepted` and nothing here asks again.
 *
 * Failures other than the two named outcomes throw, as they do on the Sync
 * page; `HostingPaymentRequiredError` is the one callers route to billing.
 */
export async function hostDriveOnPortal(
  args: HostArgs,
  deps: {
    enable: typeof enableCloudSyncForDrive;
    ensureSession: typeof ensureManagedSession;
  } = { enable: enableCloudSyncForDrive, ensureSession: ensureManagedSession },
): Promise<HostOnPortalOutcome> {
  let result = await deps.enable(args);

  if (!result.ok) {
    const portal = result.portalUrl ?? knownPortalUrl(args.managedInfo);

    if (!portal) return { status: 'no-portal' };

    if (!(await deps.ensureSession(portal))) return { status: 'cancelled' };

    result = await deps.enable(args);

    if (!result.ok) return { status: 'cancelled' };
  }

  return {
    status: 'hosted',
    httpOrigin: result.httpOrigin,
    replicated: result.replicated,
  };
}
