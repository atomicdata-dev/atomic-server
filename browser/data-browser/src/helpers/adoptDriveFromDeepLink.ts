import { enableLoro, isUnauthorized, server, type Store } from '@tomic/react';

/** Server-managed property stamping every resource with its drive at genesis. */
const DRIVE_PROP = 'https://atomicdata.dev/properties/drive';

/**
 * When the app is opened via a deep link to a resource (a `?subject=` on the
 * entry URL — share/show links) on a browser with NO established session
 * drive, the session should start in that resource's drive instead of the
 * bare server fallback. Without this, opening a share link for a resource in
 * drive X lands the guest in a sidebar/drive context that has nothing to do
 * with what they clicked.
 *
 * Gated on "no drive already adopted" (`store.getDrive()`), not merely "the
 * URL has a `?subject=`": on this codebase every resource — not just share
 * links — navigates via `constructOpenURL`'s `did:`-subject branch, which
 * always produces a `/app/show?subject=...` URL (see `helpers/navigation.tsx`).
 * `openSubject`-style navigation does a full `page.goto`/reload, so an
 * ALREADY-established session merely refreshing (or being sent) any resource
 * URL would otherwise look identical to a fresh deep link and could yank the
 * user into an unrelated drive that resource happens to be stamped with.
 * `App.tsx` calls `store.setDrive(initialDrive)` from `driveStorage` before
 * this runs, so `store.getDrive()` here already reflects "does this browser
 * have a session drive" — only a truly fresh profile (or one with its stored
 * drive cleared) has none.
 *
 * Reads the entry URL once at startup — in-app (client-side router)
 * navigation to foreign-drive resources doesn't re-run this at all, since it
 * only executes once at module load.
 *
 * The drive is read from the resource's genesis-stamped `drive` property
 * (delivered with the resource itself, so it works for a guest who cannot read
 * the drive's ancestors). `store.setDrive` persists the choice and fires
 * `DriveChanged`, so the AppSettings mirror (and its localStorage entry) stay
 * in sync whether this resolves before or after React mounts.
 */
export async function adoptDriveFromDeepLink(store: Store): Promise<void> {
  if (store.getDrive()) {
    // This browser already has a session drive (freshly restored from
    // `driveStorage` or set earlier this session) — only a driveless
    // session (a genuinely fresh profile) adopts from the entry URL.
    return;
  }

  const subject = new URLSearchParams(window.location.search).get('subject');

  if (!subject) {
    return;
  }

  try {
    // Both the WS handshake and the Loro WASM load are async and racing this
    // startup path. The subject's properties (`drive`, `isA`) live in the
    // resource's Loro doc, so reading them before Loro is initialized returns
    // nothing — `getResource` resolves, but against an un-materialized doc.
    // Wait out both before fetching so the fetched resource is actually
    // readable.
    if (subject.startsWith('did:') && !store.serverConnected) {
      // `did:` subjects have no HTTP fallback: `store.getResource` can only
      // resolve them once the WS is connected. A page load always starts
      // disconnected and reconnects within a few hundred ms, so give it a
      // moment rather than losing the adoption to that race every time.
      await store.waitForServerConnected(5000);
    }

    await enableLoro();

    const resource = await store.getResource(subject);

    if (resource.error) {
      return;
    }

    // Genesis stamps `drive` on every resource that has a parent (a child gets
    // its parent's drive). A resource with NO `drive` prop is itself a drive
    // root — "top-level resources ARE their own drive" (see `commit.rs`). So:
    //   - drive prop present  → adopt THAT (the resource's drive)  ← the case
    //     this feature is for: a deep link to a resource lands you in its drive
    //   - drive prop absent + the resource IS a Drive → adopt the subject
    //   - anything else → don't guess (never adopt a non-drive resource as its
    //     own drive; walking the parent chain would return the resource itself
    //     for an unresolvable ancestry and do exactly that)
    const driveProp = resource.get(DRIVE_PROP) as string | undefined;
    let drive: string | undefined;

    if (typeof driveProp === 'string' && driveProp.length > 0) {
      drive = driveProp;
    } else if (resource.getClasses().includes(server.classes.drive)) {
      drive = subject;
    }

    if (!drive || drive === store.getDrive()) {
      return;
    }

    store.setDrive(drive);
  } catch (e) {
    // An anonymous private link stays driveless until the sign-in flow unlocks
    // it. Its access-denied resource renders that flow; adoption did not fail.
    if (!store.getAgent() && e instanceof Error && isUnauthorized(e)) return;
    // Resource unreachable — keep the current drive.
    console.warn('[adoptDriveFromDeepLink] could not resolve drive:', e);
  }
}
