import { useEffect, useEffectEvent, type JSX } from 'react';
import { isAtomicIdentifier, looksLikePairingUri } from '@tomic/lib';
import { clearDeepLinkSink, setDeepLinkSink } from '../helpers/deepLinkQueue';
import { constructOpenURL } from '../helpers/navigation';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { paths } from '../routes/paths';
import { usePairingFlow } from './pairing/PairingFlowProvider';

/** Legacy `atomic://open?subject=…` deep link. */
const OPEN_LINK_PREFIX = 'atomic://open';

/** `atomic://authorize-mcp?…`: `atomic-mcp connect --desktop` asking to be approved here. */
const AUTHORIZE_MCP_PREFIX = 'atomic://authorize-mcp';

function parseOpenLinkSubject(uri: string): string | null {
  if (!uri.startsWith(OPEN_LINK_PREFIX)) {
    return null;
  }

  try {
    return new URL(uri).searchParams.get('subject');
  } catch {
    return null;
  }
}

/**
 * Consumes deep links forwarded by the Tauri shell and routes them:
 *
 * - a node identifier (`atomic:node:…`, including query hints) starts pairing
 * - any other Atomic identifier navigates to that resource
 * - legacy `atomic://open?subject=…` and `atomic://pair?…` still work
 *
 * A pairing code is routing only, so this can act on one without asking.
 */
export function PairingLinkHandler(): JSX.Element {
  const startPairing = usePairingFlow();
  const navigate = useNavigateWithTransition();

  const handleLink = useEffectEvent((uri: string) => {
    if (uri.startsWith(OPEN_LINK_PREFIX)) {
      const subject = parseOpenLinkSubject(uri);

      if (subject) {
        navigate(constructOpenURL(subject));
      }

      return;
    }

    if (uri.startsWith(AUTHORIZE_MCP_PREFIX)) {
      try {
        // The consent page checks the server and the redirect itself.
        const { searchParams } = new URL(uri);

        navigate(`${paths.authorizeMcp}?${searchParams}`);
      } catch {
        // Not a link we can read: nothing to approve.
      }

      return;
    }

    if (looksLikePairingUri(uri)) {
      startPairing(uri);

      return;
    }

    const identifier = uri.split(/[?#]/)[0];

    if (isAtomicIdentifier(identifier)) {
      navigate(constructOpenURL(identifier));
    }
  });

  useEffect(() => {
    const sink = (uri: string) => handleLink(uri);
    setDeepLinkSink(sink);

    return () => clearDeepLinkSink(sink);
  }, []);

  return <></>;
}
