import { useEffect, useState } from 'react';
import { peerLinkStatus, PEER_LINK_CHANGED } from '../helpers/browserPeerSync';
import { getManagedPortalUrl } from '../helpers/managed/cloudSync';
import { safePortalUrl } from '../helpers/managed/api';
import { openExternal } from '../helpers/openExternal';

function OfferLink({ offer }: { offer: string }) {
  return (
    <a
      href={offer}
      target='_blank'
      rel='noreferrer'
      onClick={e => {
        e.preventDefault();
        void openExternal(offer);
      }}
    >
      See Cloud Server plans
    </a>
  );
}

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

  if (status === /* @wc-ignore */ 'Too many peer sessions') {
    const portal = safePortalUrl(getManagedPortalUrl());
    let offer: string | null = null;

    if (portal) {
      const url = new URL(portal);
      url.searchParams.set('tier', 'server');
      if (drive) url.searchParams.set('drive', drive);
      url.hash = 'pricing';
      offer = url.toString();
    }

    return (
      <small role='status'>
        <span>
          Browser sync has reached its limit of peer connections. A Cloud Server
          on atomic.place keeps this workspace in sync for everyone, without
          peers.
        </span>
        {offer && <OfferLink offer={offer} />}
      </small>
    );
  }

  return <small role='status'>Browser sync · {status}</small>;
}
