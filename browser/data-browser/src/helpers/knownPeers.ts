// The local list of paired peer nodes ('atomic-peers' in localStorage) — the
// capability records auto-dial uses. Written by explicit user action only:
// the Sync page's peer flow, a scanned/pasted atomic:pair link, or the
// account device directory. The Sync page renders and syncs these.

const KNOWN_PEERS_KEY = 'atomic-peers';
const NODE_DID_PREFIX = 'did:ad:node:';

export type KnownPeer = { nodeId: string; label: string; lastSync?: string };

export function readKnownPeers(): KnownPeer[] {
  try {
    return (
      JSON.parse(localStorage.getItem(KNOWN_PEERS_KEY) ?? '[]') as KnownPeer[]
    ).filter(peer =>
      /^[0-9a-f]{64}$/i.test(peer.nodeId?.slice(NODE_DID_PREFIX.length) ?? ''),
    );
  } catch {
    return [];
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
      label: label ?? `${nodeDid.slice(0, NODE_DID_PREFIX.length + 8)}...`,
    });
  }

  try {
    localStorage.setItem(KNOWN_PEERS_KEY, JSON.stringify(peers));
  } catch {
    // Quota / private mode — the record is re-creatable by pairing again.
  }
}
