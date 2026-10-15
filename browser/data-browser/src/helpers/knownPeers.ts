// The local list of paired peer nodes ('atomic-peers' in localStorage) — the
// capability records auto-dial uses. Written by explicit user action only:
// the Sync page's peer flow, a scanned/pasted atomic://pair link, or the
// account device directory. The Sync page renders and syncs these.

import { nodeId } from '@tomic/lib';

const KNOWN_PEERS_KEY = 'atomic-peers';

export type KnownPeer = { nodeId: string; label: string; lastSync?: string };

function nodeHex(nodeDid: string | undefined): string | undefined {
  const hex = nodeId(nodeDid ?? '')?.split(':')[0];

  return hex && /^[0-9a-f]{64}$/i.test(hex) ? hex : undefined;
}

export function readKnownPeers(): KnownPeer[] {
  try {
    return (
      JSON.parse(localStorage.getItem(KNOWN_PEERS_KEY) ?? '[]') as KnownPeer[]
    ).filter(peer => !!nodeHex(peer.nodeId));
  } catch {
    return [];
  }
}

/** Replace the stored list. Swallows storage errors (quota, private mode). */
export function writeKnownPeers(peers: KnownPeer[]): void {
  try {
    localStorage.setItem(KNOWN_PEERS_KEY, JSON.stringify(peers));
  } catch {
    // Quota / private mode — the records are re-creatable by pairing again.
  }
}

/** Add or refresh a peer record. Existing labels win over generic fallbacks. */
export function upsertKnownPeer(nodeDid: string, label?: string): void {
  const peers = readKnownPeers();
  const existing = peers.find(
    peer => peer.nodeId.toLowerCase() === nodeDid.toLowerCase(),
  );

  if (existing) {
    if (label) {
      existing.label = label;
    }
  } else {
    peers.push({
      nodeId: nodeDid,
      label: label ?? `${nodeDid.slice(0, 20)}...`,
    });
  }

  writeKnownPeers(peers);
}
