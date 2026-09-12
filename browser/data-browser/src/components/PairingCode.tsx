import { useMemo, type JSX } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { renderSVG } from 'uqr';
import { encodePairingEnvelope, type PairingEnvelope } from '@tomic/lib';
import { Button } from './Button';
import { useSettings } from '../helpers/AppSettings';

interface PairingCodeProps {
  /** The Iroh identity to advertise: `did:ad:node:<64 hex>`. */
  nodeDid: string;
}

/**
 * An `atomic:pair` code for `nodeDid`, as a QR and as copyable text, for
 * another device to scan or paste.
 *
 * The node is whichever one another device should reach to sync: this device
 * when the app is itself a peer node, or the server it is signed in to when it
 * is not — a browser tab is not a node, but the server behind it is.
 *
 * The code names the drive it is shown for, which is the point of `drives`:
 * "the field that tells a freshly signed-in device *which* drive to pull"
 * (planning/device-pairing.md). A device with a secret and nothing else has no
 * drive to ask for — a code saying `*` leaves it exactly as stuck as before it
 * scanned, because "all of them" names none of them.
 *
 * The code is **routing only** — it says where to reach a node and what to ask
 * it for, and grants neither. Whoever dials still has to prove they hold a key
 * that may read the drive, so this is safe to show on screen.
 */
export function PairingCode({ nodeDid }: PairingCodeProps): JSX.Element {
  const { baseURL, drive } = useSettings();

  // A LAN/WS fast path is only worth advertising when another device could
  // actually reach it — localhost never resolves to this machine elsewhere.
  const urlHint = useMemo(() => {
    try {
      const parsed = new URL(baseURL);

      return parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1'
        ? undefined
        : baseURL;
    } catch {
      return undefined;
    }
  }, [baseURL]);

  const pairUri = useMemo(() => {
    // Name a *specific* drive, which is a workspace DID. When the active drive
    // is the server origin itself, no particular workspace is selected — that
    // is the pre-DID default (`useLocalStorage('drive', baseURL)`) showing
    // through, and "the whole server" is `*`, not a drive to pull.
    const namedDrive = drive && drive !== baseURL ? [drive] : '*';

    const envelope: PairingEnvelope = {
      v: 1,
      node: nodeDid,
      ...(urlHint ? { url: urlHint } : {}),
      drives: namedDrive,
    };

    return encodePairingEnvelope(envelope);
  }, [nodeDid, urlHint, drive, baseURL]);

  const pairSvg = useMemo(() => renderSVG(pairUri), [pairUri]);

  const copyCode = async () => {
    try {
      await navigator.clipboard.writeText(pairUri);
      toast.success('Pairing code copied.');
    } catch {
      toast.error('Could not copy — select and copy the code manually.');
    }
  };

  return (
    <>
      <QrBox dangerouslySetInnerHTML={{ __html: pairSvg }} />
      <CodeRow>
        <CodeText title={pairUri}>{pairUri}</CodeText>
        <Button subtle onClick={copyCode}>
          Copy
        </Button>
      </CodeRow>
    </>
  );
}

/* `width: 100%` matters: inside a centered column the row would otherwise size
   to its content, and the code — one long unbroken token — would push past the
   card instead of ellipsing. */
const CodeRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.6rem;
  margin-bottom: 0.4rem;
  width: 100%;
  min-width: 0;
`;

const CodeText = styled.code`
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 0.75rem;
  color: ${p => p.theme.colors.textLight};
  background: ${p => p.theme.colors.bg1};
  padding: 0.35rem 0.5rem;
  border-radius: ${p => p.theme.radius};
`;

const QrBox = styled.div`
  width: 13rem;
  height: 13rem;
  max-width: 100%;
  border-radius: ${p => p.theme.radius};
  overflow: hidden;
  background: white;
  padding: 0.5rem;
  box-sizing: border-box;

  svg {
    width: 100%;
    height: 100%;
    display: block;
  }
`;
