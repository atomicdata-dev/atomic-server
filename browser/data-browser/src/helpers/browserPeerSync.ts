import { readTemplateDemo } from '../chunks/Templates/demoSession';
import { isLoopbackHost } from './runtimeSetting';
import { fetchManagedInfo } from './managedServer';
import {
  BrowserPeerSync,
  randomPeerToken,
  server,
  type Store,
  isAtomicIdentifier,
  isAgentSubject,
} from '@tomic/lib';

export interface SavedPeerLink {
  drive: string;
  room: string;
  signalingUrl: string;
  expectedPeer?: string;
  invitation?: string;
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
  if (
    savedPeerLinks(store).some(
      existing => JSON.stringify(existing) === JSON.stringify(link),
    )
  )
    return;
  const links = savedPeerLinks(store).filter(
    existing => existing.drive !== link.drive,
  );
  localStorage.setItem(key(store), JSON.stringify([...links, link]));
  active.get(store)?.get(link.drive)?.close();
  active.get(store)?.delete(link.drive);
  active.get(store)?.get(`automatic:${link.drive}`)?.close();
  active.get(store)?.delete(`automatic:${link.drive}`);
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

/** Local storage key for a signalling service the person chose themselves. */
export const PEER_SIGNALING_SETTING = 'peer-signaling-url';

export const NO_PEER_SIGNALING =
  'Peer-to-peer sharing needs a signalling service, and none is configured. Nothing is contacted until one is.';

function chosenSignalingUrl(): URL | null {
  try {
    const chosen = localStorage.getItem(PEER_SIGNALING_SETTING);
    if (!chosen) return null;
    const url = new URL(chosen);
    const secure = url.protocol === 'wss:' || url.protocol === 'https:';
    const loopback =
      (url.protocol === 'ws:' || url.protocol === 'http:') &&
      isLoopbackHost(url.hostname);

    return secure || loopback ? url : null;
  } catch {
    return null;
  }
}

/**
 * The signalling service peers meet through, or null when none is configured.
 *
 * There is no built-in default. Discovery announces a hash of every local drive
 * and the device's address to whoever runs the service, so a build that was not
 * pointed at one contacts nobody. A hosted distribution is compiled against its
 * own portal (`VITE_MANAGED_PORTAL_URL`), a community rendezvous is named with
 * `VITE_ATOMIC_SIGNALING_URL`, and a person can choose one at runtime with the
 * `peer-signaling-url` setting. An app served from a SaaS staging host keeps
 * using that host's service, since it already talks to it.
 */
export function configuredPeerSignalingUrl(): string | null {
  const explicit = import.meta.env.VITE_ATOMIC_SIGNALING_URL;
  const portal =
    import.meta.env.VITE_MANAGED_PORTAL_URL ||
    (window.location.hostname === 'staging.atomicserver.eu' ||
    window.location.hostname.endsWith('.staging.atomicserver.eu')
      ? 'https://staging.atomicserver.eu'
      : undefined);
  let endpoint: URL | null = chosenSignalingUrl();

  try {
    if (!endpoint && (explicit || portal))
      endpoint = new URL(explicit || '/webrtc-signal', portal);
  } catch {
    return null;
  }

  if (!endpoint) return null;
  if (endpoint.protocol === 'https:') endpoint.protocol = 'wss:';
  if (endpoint.protocol === 'http:') endpoint.protocol = 'ws:';

  return endpoint.toString();
}

/** For actions the person started: refuse instead of quietly dialling nobody. */
export function requirePeerSignalingUrl(): string {
  const url = configuredPeerSignalingUrl();
  if (!url) throw new Error(NO_PEER_SIGNALING);

  return url;
}

export function createPeerLink(
  store: Store,
  drive: string,
): { link: SavedPeerLink; invitation: string } {
  const link = savedPeerLinks(store).find(
    existing => existing.drive === drive,
  ) ?? {
    drive,
    room: randomPeerToken(),
    signalingUrl: requirePeerSignalingUrl(),
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
    !isAtomicIdentifier(link.drive) ||
    link.drive.includes('#') ||
    link.drive.includes('?') ||
    !/^[a-f0-9]{64}$/.test(link.room) ||
    typeof link.expectedPeer !== 'string' ||
    !isAgentSubject(link.expectedPeer) ||
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

/** Discovery is not authorization: signed sessions still enforce drive ACLs. */
export async function automaticPeerRoom(drive: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`atomic-browser-drive-v1:${drive}`),
  );

  return Array.from(new Uint8Array(digest), byte =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

const discovering = new WeakSet<Store>();
const managedByOrigin = new Map<string, Promise<boolean>>();

/**
 * Does this drive sync through a Cloud Server? Such a drive reaches every member
 * through the node, so peers add nothing and only spend the shared budget of
 * peer sessions: a member with many drives hit "Too many peer sessions" while
 * their data was already on the server. Answered per server, once.
 */
export async function driveUsesCloudServer(
  store: Store,
  drive: string,
): Promise<boolean> {
  const serverUrl = store.getServerUrl();

  if (!serverUrl || !store.isLiveSyncedDrive(drive)) return false;

  let managed = managedByOrigin.get(serverUrl);

  if (!managed) {
    managed = fetchManagedInfo(serverUrl).then(info => info.managed);
    managedByOrigin.set(serverUrl, managed);
  }

  return managed;
}

export async function discoverPeerDrives(store: Store): Promise<void> {
  const agent = store.getAgent();
  const db = store.getClientDb();
  // Automatic discovery is background traffic nobody asked for: with no
  // configured service it must not reach anywhere at all.
  const signalingUrl = configuredPeerSignalingUrl();
  if (!signalingUrl || !agent || !db || discovering.has(store)) return;
  discovering.add(store);
  let links = active.get(store);

  if (!links) {
    links = new Map();
    active.set(store, links);
  }

  const current = () =>
    store.getAgent() === agent &&
    store.getClientDb() === db &&
    active.get(store) === links;

  try {
    for (const resource of store.resources.values()) {
      const drive = resource.subject;
      const id = `automatic:${drive}`;

      if (
        resource.isReady() &&
        resource.hasClasses(server.classes.drive) &&
        (await driveUsesCloudServer(store, drive))
      ) {
        links.get(id)?.close();
        links.delete(id);
        continue;
      }

      if (!current()) return;

      if (
        readTemplateDemo()?.drive === drive ||
        !isAtomicIdentifier(drive) ||
        !resource.isReady() ||
        resource.error ||
        !resource.hasClasses(server.classes.drive) ||
        links.has(id) ||
        savedPeerLinks(store).some(link => link.drive === drive)
      )
        continue;

      try {
        // Never bootstrap trust from a discovered stranger's snapshot.
        if (!(await db.getResourceWithSnapshot(drive)).snapshot) continue;
        const room = await automaticPeerRoom(drive);
        if (!current()) return;
        links.set(
          id,
          new BrowserPeerSync(store, {
            drive,
            room,
            signalingUrl,
            iceServers: import.meta.env.VITE_ATOMIC_ICE_SERVERS
              ? JSON.parse(import.meta.env.VITE_ATOMIC_ICE_SERVERS)
              : undefined,
            onStatus: status => {
              if (!current()) return;
              statuses.set(drive, status);
              window.dispatchEvent(new Event(PEER_LINK_CHANGED));
            },
          }),
        );
      } catch {
        /* Retry after local storage becomes ready. */
      }
    }
  } finally {
    discovering.delete(store);
  }
}
