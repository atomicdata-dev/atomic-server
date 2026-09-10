import { useEffect, useState } from 'react';
import { peerLinkStatus, PEER_LINK_CHANGED } from '../helpers/browserPeerSync';

export function BrowserPeerPanel({ drive }: { drive?: string }) {
  const [status, setStatus] = useState('');
  useEffect(() => {
    const update = () => setStatus(drive ? peerLinkStatus(drive) : '');
    update();
    window.addEventListener(PEER_LINK_CHANGED, update);

    return () => window.removeEventListener(PEER_LINK_CHANGED, update);
  }, [drive]);
  if (!status.startsWith(/* @wc-ignore */ 'Connected to')) return null;

  return <small role='status'>{status}</small>;
}
