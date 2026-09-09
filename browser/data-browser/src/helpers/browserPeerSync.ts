import { BrowserPeerSync, randomPeerToken, type Store } from '@tomic/lib';

export interface SavedPeerLink {
  drive: string;
  room: string;
  signalingUrl: string;
  expectedPeer?: string;
}
const active = new WeakMap<Store, Map<string, BrowserPeerSync>>();
const statuses = new Map<string, string>();

export const PEER_LINK_CHANGED = 'atomic-peer-link-changed';
const key = (store: Store) => `atomic.peerLinks.${store.getAgent()?.subject}`;

export function savedPeerLinks(store: Store): SavedPeerLink[] {
  try {
    const links: unknown = JSON.parse(localStorage.getItem(key(store)) ?? '[]');
    if (!Array.isArray(links)) return [];

    return links.filter(
      (link): link is SavedPeerLink =>
        !!link &&
        typeof link.drive === 'string' &&
        typeof link.signalingUrl === 'string' &&
        typeof link.room === 'string' &&
        /^[a-f0-9]{64}$/.test(link.room) &&
        (link.expectedPeer === undefined ||
          typeof link.expectedPeer === 'string'),
    );
  } catch {
    return [];
  }
}

export function peerLinkStatus(drive: string): string {
  return statuses.get(drive) ?? 'Not connected';
}

export function savePeerLink(store: Store, link: SavedPeerLink): void {
  const links = savedPeerLinks(store).filter(
    existing => existing.drive !== link.drive,
  );
  localStorage.setItem(key(store), JSON.stringify([...links, link]));
  active.get(store)?.get(link.drive)?.close();
  active.get(store)?.delete(link.drive);
  window.dispatchEvent(new Event(PEER_LINK_CHANGED));
}

export function removePeerLink(store: Store, drive: string): void {
  localStorage.setItem(
    key(store),
    JSON.stringify(savedPeerLinks(store).filter(link => link.drive !== drive)),
  );
  active.get(store)?.get(drive)?.close();
  active.get(store)?.delete(drive);
  statuses.delete(drive);
  window.dispatchEvent(new Event(PEER_LINK_CHANGED));
}

export function resumePeerLinks(store: Store): void {
  if (!store.getAgent() || !store.getClientDb()) return;
  let links = active.get(store);

  if (!links) {
    links = new Map();
    active.set(store, links);
  }

  for (const link of savedPeerLinks(store)) {
    if (links.has(link.drive)) continue;

    try {
      links.set(
        link.drive,
        new BrowserPeerSync(store, {
          ...link,
          iceServers: import.meta.env.VITE_ATOMIC_ICE_SERVERS
            ? JSON.parse(import.meta.env.VITE_ATOMIC_ICE_SERVERS)
            : undefined,
          onStatus: status => {
            statuses.set(link.drive, status);
            window.dispatchEvent(new Event(PEER_LINK_CHANGED));
          },
        }),
      );
    } catch (error) {
      statuses.set(link.drive, String(error));
    }
  }
}

export function stopPeerLinks(store: Store): void {
  for (const link of active.get(store)?.values() ?? []) link.close();
  active.delete(store);
  statuses.clear();
}

export function createPeerLink(
  store: Store,
  drive: string,
): { link: SavedPeerLink; invitation: string } {
  const endpoint = new URL(
    import.meta.env.VITE_ATOMIC_SIGNALING_URL || '/webrtc-signal',
    store.getServerUrl(),
  );
  if (endpoint.protocol === 'https:') endpoint.protocol = 'wss:';
  if (endpoint.protocol === 'http:') endpoint.protocol = 'ws:';
  const link = {
    drive,
    room: randomPeerToken(),
    signalingUrl: endpoint.toString(),
  };
  const invite = { ...link, expectedPeer: store.getAgent()?.subject };
  const url = new URL('/app/sync', window.location.origin);
  url.searchParams.set('drive', drive);
  url.hash = `peer=${btoa(JSON.stringify(invite))}`;

  return { link, invitation: url.toString() };
}

export function parsePeerLink(invitation: string): SavedPeerLink {
  const url = new URL(invitation);
  const encoded = new URLSearchParams(url.hash.slice(1)).get('peer');
  if (!encoded || encoded.length > 8192) throw new Error('Invalid peer link');
  const link = JSON.parse(atob(encoded));
  if (
    typeof link.drive !== 'string' ||
    !link.drive.startsWith('did:ad:') ||
    link.drive.includes('#') ||
    link.drive.includes('?') ||
    !/^[a-f0-9]{64}$/.test(link.room) ||
    typeof link.expectedPeer !== 'string' ||
    !link.expectedPeer.startsWith('did:ad:agent:') ||
    typeof link.signalingUrl !== 'string'
  )
    throw new Error('Invalid peer link');

  return {
    drive: link.drive,
    room: link.room,
    signalingUrl: link.signalingUrl,
    expectedPeer: link.expectedPeer,
  };
}
