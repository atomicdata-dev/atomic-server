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
  if (
    !status ||
    status === /* @wc-ignore */ 'Not connected' ||
    status === /* @wc-ignore */ 'Disconnected'
  )
    return null;

  return <small role='status'>Browser sync · {status}</small>;
}
