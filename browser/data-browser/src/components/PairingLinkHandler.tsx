import { useEffect, useEffectEvent, type JSX } from 'react';
import { clearDeepLinkSink, setDeepLinkSink } from '../helpers/deepLinkQueue';
import { constructOpenURL } from '../helpers/navigation';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { usePairingFlow } from './pairing/PairingFlowProvider';
import { paths } from '../routes/paths';

/**
 * The `atomic:open` link: "open this resource". Older links carry a `//`
 * after the scheme; both are ours.
 */
const isOpenLink = (uri: string): boolean =>
  uri.startsWith('atomic:open') || uri.startsWith('atomic://open');

const isAtomicLink = (uri: string): boolean => uri.startsWith('atomic:');

/**
 * The query of an `atomic:open?subject=…` link, or null if it is malformed.
 * Kept at module scope so its try/catch stays out of component render, which
 * the React Compiler can't yet handle.
 */
function parseOpenLink(uri: string): URLSearchParams | null {
  try {
    return new URL(uri.replace(/^atomic:\/\//, 'atomic:')).searchParams;
  } catch {
    return null;
  }
}

/**
 * Consumes deep links forwarded by the Tauri shell (queued by
 * helpers/deepLinkQueue.ts) and routes them:
 *
 * - `atomic:open?subject=…` opens a resource in the app. The virtual drive
 *   surfaces non-file resources as `.inetloc` link files pointing here, so
 *   double-clicking one in Finder navigates the desktop app to that resource.
 *   With a `cap` parameter it is a capability link (`@tomic/lib`
 *   `capability.ts`) and goes to `/app/open`, which redeems the right it
 *   carries before navigating.
 * - `atomic:pair` (and a bare node DID from the Sync page's paste field) go
 *   to the pairing flow, which shows its progress and reports what happened.
 *
 * A pairing code is routing only, so this can act on one without asking. It
 * grants nothing — the dialed peer still has to pass same-agent AUTH — and a
 * code that tries to carry an identity is refused when it's decoded. That
 * refusal is what makes acting-without-asking safe here: `atomic:` links can
 * be fired by any app or web page, not just by the camera, so a link must never
 * be able to sign this device in as someone else. An `open` link only navigates
 * to a resource the user can already reach, so it is likewise safe to act on.
 */
export function PairingLinkHandler(): JSX.Element {
  const startPairing = usePairingFlow();
  const navigate = useNavigateWithTransition();

  const handleLink = useEffectEvent((uri: string) => {
    // `atomic:open` links navigate to a resource rather than pairing. Consume
    // them here even when malformed, so a bad open link never falls through to
    // the pairing flow.
    if (isOpenLink(uri)) {
      const params = parseOpenLink(uri);
      const subject = params?.get('subject');

      if (params?.has('cap')) {
        // A capability link: redeem it, do not merely navigate.
        navigate(`${paths.open}?${params.toString()}`);
      } else if (subject) {
        navigate(constructOpenURL(subject));
      }

      return;
    }

    // Deep links from the OS always arrive as `atomic:…`. The Sync page's
    // paste field feeds this same pipeline, and there a bare node DID is a
    // legitimate (routing-only) code. Anything else isn't ours.
    if (!isAtomicLink(uri) && !uri.startsWith('did:ad:node:')) {
      return;
    }

    startPairing(uri);
  });

  useEffect(() => {
    const sink = (uri: string) => handleLink(uri);
    setDeepLinkSink(sink);

    return () => clearDeepLinkSink(sink);
  }, []);

  return <></>;
}
