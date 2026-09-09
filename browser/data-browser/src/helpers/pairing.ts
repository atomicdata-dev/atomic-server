// @wc-ignore-file
// Pairing side-effects, shared by every surface that accepts a pairing code:
// the deep-link handler, the Sync page's dialog, and the post-sign-in
// "connect a device" screen.
//
// Recording a peer grants it nothing. `atomic://pair` codes are routing only:
// the dialed node still has to prove it holds the same agent key over AUTH
// before a single resource crosses. See planning/device-pairing.md.

import {
  decodePairingEnvelope,
  PairingEnvelopeError,
  signRequest,
  type Agent,
} from '@tomic/lib';
import { upsertKnownPeer } from './knownPeers';
import { getLocalServerOrigin } from './tauri';

export type PeerSyncOutcome = {
  /** Resources reconciled in both directions. */
  count: number;
  /** The peer's self-reported name, when it speaks HELLO. */
  peerName?: string;
};

/**
 * Remember the peer, then pull the drive from it. Reconciliation is
 * bidirectional, so this both fetches what this device is missing and hands
 * the peer whatever it lacks.
 *
 * Returns `undefined` when there is no drive to sync yet — the peer is still
 * recorded, so a later sync (Sync page, auto-connect) can use it.
 *
 * `agent` signs the request: the node only dials a peer on behalf of an agent
 * with write rights on the drive. Without one the request goes out unsigned
 * and the node's refusal is what the caller sees.
 *
 * Throws with a message fit to show the user.
 */
export async function pairAndSync(
  nodeDid: string,
  drive: string | undefined,
  agent: Agent | undefined,
): Promise<PeerSyncOutcome | undefined> {
  upsertKnownPeer(nodeDid);

  if (!drive) {
    return undefined;
  }

  // Absolute origin: a bare path hits `tauri.localhost`, not the embedded
  // server, inside the desktop/mobile webview.
  const url = `${getLocalServerOrigin()}/iroh-sync`;
  const baseHeaders = { 'Content-Type': 'application/json' };
  const headers = agent
    ? await signRequest(url, agent, baseHeaders)
    : baseHeaders;

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({ nodeId: nodeDid, drive }),
  });
  // A refusal (401/403) may not carry JSON; still say what happened.
  const data = await response.json().catch(() => ({
    error: `${response.status} ${response.statusText}`.trim(),
  }));

  if (data.error) {
    throw new Error(String(data.error));
  }

  const peerName: string | undefined =
    typeof data.peerName === 'string' && data.peerName.trim()
      ? data.peerName.trim()
      : undefined;

  // Now that the peer has introduced itself, replace the truncated-DID
  // placeholder label with its name.
  if (peerName) {
    upsertKnownPeer(nodeDid, peerName);
  }

  return { count: Number(data.count) || 0, peerName };
}

export type PairingRunResult =
  | { ok: true; outcome: PeerSyncOutcome | undefined }
  | { ok: false; message: string };

/**
 * Decode a scanned/pasted code and act on it, reporting failure as a value.
 *
 * The throwing version is awkward to drive a UI with: React components that
 * `await` inside try/catch defeat the compiler's memoisation (see the
 * data-browser CLAUDE.md), and every caller wants the same three messages
 * anyway.
 */
export async function runPairing(
  code: string,
  drive: string | undefined,
  agent: Agent | undefined,
): Promise<PairingRunResult> {
  let node: string;

  try {
    node = decodePairingEnvelope(code).node;
  } catch (e) {
    return {
      ok: false,
      message:
        e instanceof PairingEnvelopeError
          ? e.message
          : 'Could not read that pairing code.',
    };
  }

  try {
    return { ok: true, outcome: await pairAndSync(node, drive, agent) };
  } catch (e) {
    return {
      ok: false,
      message:
        e instanceof Error
          ? e.message
          : 'Could not reach that device. Make sure both are online.',
    };
  }
}
