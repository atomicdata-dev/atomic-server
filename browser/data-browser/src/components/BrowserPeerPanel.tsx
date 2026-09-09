import { isClientDbEnabled, setClientDbEnabled } from '../helpers/clientDbMode';
import { useEffect, useState } from 'react';
import { useStore } from '@tomic/react';
import { Card } from './Card';
import { Column, Row } from './Row';
import { Button } from './Button';
import { TextAreaStyled } from './forms/InputStyles';
import {
  createPeerLink,
  parsePeerLink,
  savePeerLink,
  removePeerLink,
  savedPeerLinks,
  peerLinkStatus,
  PEER_LINK_CHANGED,
} from '../helpers/browserPeerSync';

export function BrowserPeerPanel({ drive }: { drive?: string }) {
  const store = useStore();
  const [invitation, setInvitation] = useState(() =>
    window.location.hash.startsWith('#peer=') ? window.location.href : '',
  );
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [enabled, setEnabled] = useState(false);
  useEffect(() => {
    const update = () => {
      setStatus(drive ? peerLinkStatus(drive) : '');
      setEnabled(savedPeerLinks(store).some(link => link.drive === drive));
    };

    update();
    window.addEventListener(PEER_LINK_CHANGED, update);

    return () => window.removeEventListener(PEER_LINK_CHANGED, update);
  }, [drive, store]);

  const create = () => {
    if (!drive) return;
    const result = createPeerLink(store, drive);
    savePeerLink(store, result.link);

    if (!isClientDbEnabled()) {
      setClientDbEnabled(true);
      window.history.replaceState(null, '', result.invitation);
      window.location.reload();

      return;
    }

    setInvitation(result.invitation);
    setError('');
  };

  const connect = () => {
    try {
      const link = parsePeerLink(invitation);
      if (drive && drive !== link.drive)
        throw new Error('Open the peer link to select its workspace first');
      const existing = store.resources.get(link.drive);
      if (!existing?.isReady() || existing.error)
        store.registerLocalOnlyDrive(link.drive);
      savePeerLink(store, link);

      if (!isClientDbEnabled()) {
        setClientDbEnabled(true);
        window.location.reload();
      }

      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Card data-testid='peer-sync-panel'>
      <Card.Content>
        <Column>
          <h2>Peer sync</h2>
          <p>
            Sync and collaborate between open browsers. No Cloud subscription
            required. Changes catch up when both devices are online.
          </p>
          <p>
            Pair another device signed in as you, or someone who already has
            workspace access. Use Share to manage their permissions.
          </p>
          <Row>
            <Button onClick={create} disabled={!drive || !store.getAgent()}>
              Create peer link
            </Button>
            {enabled && drive && (
              <Button onClick={() => removePeerLink(store, drive)}>
                Disconnect
              </Button>
            )}
          </Row>
          <label htmlFor='browser-peer-link'>Peer link</label>
          <TextAreaStyled
            id='browser-peer-link'
            rows={3}
            value={invitation}
            onChange={event => setInvitation(event.target.value)}
          />
          <Row>
            <Button onClick={connect} disabled={!invitation}>
              Connect
            </Button>
            <Button
              onClick={() => navigator.clipboard.writeText(invitation)}
              disabled={!invitation}
            >
              Copy link
            </Button>
          </Row>
          <p role='status'>{status}</p>
          {error && <p role='alert'>{error}</p>}
        </Column>
      </Card.Content>
    </Card>
  );
}
