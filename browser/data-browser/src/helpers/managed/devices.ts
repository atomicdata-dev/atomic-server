// @wc-ignore-file
// Device-directory client: the browser/app side of zero-scan pairing.
//
// The control plane keeps a per-account list of the user's own devices
// (`GET /api/devices`, `PUT/DELETE /api/devices/{device_id}`) so a fresh
// sign-in can discover where to sync from without a QR scan. The records are
// routing hints only — a wrong node id dials a stranger that fails same-agent
// AUTH and receives nothing — so this must never gate anything.
//
// FOSS guardrail: this client runs in the browser under the user's managed
// session (like the rest of helpers/managed/*); the open-core server never
// phones home. Without a session every function here is a no-op.
//
// Canonical design: planning/device-pairing.md (§ SaaS-assisted pairing).

import { managedFetch } from './api';
import { getManagedAccount } from './session';
import { getLocalServerOrigin, isRunningInTauri } from '../tauri';
import { pairAndSync } from '../pairing';
import type { Agent } from '@tomic/lib';

const DEVICE_ID_KEY = 'atomic-device-id';
const KNOWN_PEERS_KEY = 'atomic-peers';
const NODE_DID_PREFIX = 'did:ad:node:';

export type DeviceRecord = {
  device_id: string;
  name: string;
  platform: string;
  node_id: string;
  relay_hint?: string | null;
  http_origin?: string | null;
  created_at: number;
  last_seen: number;
};

/**
 * Stable per-install identifier; the key of our own directory record.
 *
 * Exported because Cloud Vault derives its lane id from the same value — one
 * install should be one lane, and minting a second identifier would give the
 * same device two lanes that each start at segment 1.
 */
export function getOrCreateDeviceId(): string | null {
  if (typeof localStorage === 'undefined') return null;

  try {
    const existing = localStorage.getItem(DEVICE_ID_KEY);

    if (existing) return existing;

    const fresh = crypto.randomUUID();
    localStorage.setItem(DEVICE_ID_KEY, fresh);

    return fresh;
  } catch {
    return null;
  }
}

function rotateDeviceId(): string | null {
  try {
    localStorage.removeItem(DEVICE_ID_KEY);
  } catch {
    return null;
  }

  return getOrCreateDeviceId();
}

function describeThisDevice(): { name: string; platform: string } {
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';

  if (/android/i.test(ua)) {
    return { name: 'Android device', platform: 'android' };
  }

  if (/iphone|ipad/i.test(ua)) {
    return { name: 'iOS device', platform: 'ios' };
  }

  if (/mac/i.test(ua)) {
    return { name: 'Mac', platform: 'macos' };
  }

  if (/windows/i.test(ua)) {
    return { name: 'Windows PC', platform: 'windows' };
  }

  return { name: 'Computer', platform: 'linux' };
}

function isValidNodeDid(value: string): boolean {
  const raw = value.startsWith(NODE_DID_PREFIX)
    ? value.slice(NODE_DID_PREFIX.length)
    : '';

  return /^[0-9a-f]{64}$/i.test(raw);
}

/**
 * The Iroh node identity of THIS device's embedded server. Only meaningful in
 * the Tauri app (desktop/Android), where the app is the node — a plain web tab
 * has no node of its own (`/iroh-node-id` there would name the connected
 * server, not this device).
 */
async function fetchOwnNodeDid(): Promise<string | null> {
  if (!isRunningInTauri()) return null;

  try {
    // Absolute origin: a bare path resolves against `tauri.localhost` (the
    // bundled assets), not the embedded server that owns the node identity.
    const response = await fetch(`${getLocalServerOrigin()}/iroh-node-id`);
    const data = await response.json();

    return typeof data.nodeId === 'string' && isValidNodeDid(data.nodeId)
      ? data.nodeId
      : null;
  } catch {
    return null;
  }
}

async function putDeviceRecord(
  deviceId: string,
  body: { name: string; platform: string; node_id: string },
): Promise<Response> {
  return managedFetch(`/devices/${deviceId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/**
 * Register/refresh this device in the account's directory. Tauri-only (see
 * fetchOwnNodeDid). A 409 means the stored device id belongs to another
 * account (shared machine that switched accounts): rotate the id and retry
 * once, so each account gets its own record instead of fighting over one.
 */
async function upsertOwnDeviceRecord(): Promise<void> {
  const nodeDid = await fetchOwnNodeDid();

  if (!nodeDid) return;

  const deviceId = getOrCreateDeviceId();

  if (!deviceId) return;

  const body = { ...describeThisDevice(), node_id: nodeDid };
  const response = await putDeviceRecord(deviceId, body);

  if (response.status === 409) {
    const freshId = rotateDeviceId();

    if (freshId) {
      await putDeviceRecord(freshId, body);
    }
  }
}

type KnownPeer = { nodeId: string; label: string; lastSync?: string };

/**
 * Merge the account's other devices into the local `KnownPeer` list (the same
 * localStorage records the QR pairing flow writes — the sync engine can't tell
 * the two flows apart). Existing entries win: never overwrite a label or
 * lastSync the user already has.
 */
async function seedKnownPeersFromDirectory(): Promise<string[]> {
  if (typeof localStorage === 'undefined') return [];

  const response = await managedFetch(`/devices`, {});

  if (!response.ok) return [];

  const devices = (await response.json()) as DeviceRecord[];
  const ownDeviceId = getOrCreateDeviceId();
  const ownNodeDid = await fetchOwnNodeDid();

  let peers: KnownPeer[] = [];

  try {
    peers = JSON.parse(
      localStorage.getItem(KNOWN_PEERS_KEY) ?? '[]',
    ) as KnownPeer[];
  } catch {
    peers = [];
  }

  const known = new Set(peers.map(peer => peer.nodeId.toLowerCase()));
  const otherDevices: string[] = [];
  let added = false;

  for (const device of devices) {
    if (device.device_id === ownDeviceId) continue;
    if (!isValidNodeDid(device.node_id)) continue;
    if (device.node_id === ownNodeDid) continue;

    // Every other device in the account is a candidate to auto-connect to —
    // including ones already in the local list (they may not be connected yet).
    otherDevices.push(device.node_id);

    if (known.has(device.node_id.toLowerCase())) continue;

    peers.push({ nodeId: device.node_id, label: device.name });
    known.add(device.node_id.toLowerCase());
    added = true;
  }

  if (added) {
    try {
      localStorage.setItem(KNOWN_PEERS_KEY, JSON.stringify(peers));
    } catch {
      // Quota / private mode — the seed is an optimization.
    }
  }

  return otherDevices;
}

/**
 * Dial the account's other devices so a fresh sign-in syncs WITHOUT a manual
 * "Sync now" (the last mile of zero-scan pairing). Each `/iroh-sync` reconciles
 * the drive AND registers the peer in the node's known-peers table, after which
 * the reconnect loop (`sync::peer::start`) keeps it live. Tauri-only — a web tab
 * has no node to dial from. Best-effort: an offline peer just throws and is
 * retried by the reconnect loop / the next sign-in. Same-agent only, which the
 * directory guarantees (it lists this account's devices) and AUTH enforces.
 */
async function autoConnectPeers(
  nodeIds: string[],
  drive: string | undefined,
  agent: Agent | undefined,
): Promise<void> {
  if (!isRunningInTauri() || !drive || nodeIds.length === 0) return;

  await Promise.allSettled(
    nodeIds.map(nodeId =>
      pairAndSync(nodeId, drive, agent).catch(() => undefined),
    ),
  );
}

let syncedThisSession = false;

/**
 * Best-effort, once per app session (per session that actually has a managed
 * account): announce this device to the directory, seed `KnownPeer`s from it,
 * and auto-connect the account's other devices with `drive`. Safe to call
 * repeatedly — no-ops without a session so a later sign-in still gets picked up
 * by the next call.
 */
export async function syncDeviceDirectory(
  drive?: string,
  agent?: Agent,
): Promise<void> {
  if (syncedThisSession) return;

  const account = await getManagedAccount().catch(() => null);

  if (!account) return;

  syncedThisSession = true;

  await upsertOwnDeviceRecord().catch(() => undefined);
  const peerNodeIds = await seedKnownPeersFromDirectory().catch(
    () => [] as string[],
  );
  await autoConnectPeers(peerNodeIds, drive, agent);
}
