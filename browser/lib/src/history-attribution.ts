/**
 * Who signed a resource's history.
 *
 * A node keeps signed commit envelopes per resource (`atomic_lib::envelopes`,
 * `Tree::Envelopes`): the envelope that produced the current state (`latest`
 * retention) or every envelope (`all`). Verifying them is replay: the
 * signature is checked with the same code apply uses, and the envelope's Loro
 * update names the change tokens it introduced. History buckets versions by
 * those tokens, so a version maps to its signer by lookup. Anything not
 * covered is unattributed, never a guessed signer.
 *
 * The report comes from `GET /history-attribution?subject=` on the connected
 * server, or from the local ClientDb for resources it applied itself.
 */

import type { Version } from './resource.js';

export interface Attribution {
  /** Agent subject that signed the commit. */
  signer: string;
  /** Commit `createdAt`, Unix milliseconds. */
  createdAt: number;
  signature: string;
  /** The signature checked out against the signer's key on the answering node. */
  verified: boolean;
  /** Loro change messages (drain tokens) this envelope introduced. */
  tokens: string[];
  destroy: boolean;
  genesis: boolean;
}

export interface HistoryAttribution {
  /** Pure id of the resource. */
  subject: string;
  /** `latest` or `all`: the answering node's envelope retention. */
  retention: 'latest' | 'all' | string;
  /** Oldest first. */
  attributions: Attribution[];
  /**
   * Every client-authored change in the oplog is claimed by a verified
   * envelope. `false` means History has versions nobody can be held to.
   */
  complete: boolean;
}

/** Parse the server / WASM JSON. Returns null for anything malformed. */
export function parseHistoryAttribution(
  input: unknown,
): HistoryAttribution | null {
  const data =
    typeof input === 'string'
      ? (() => {
          try {
            return JSON.parse(input);
          } catch {
            return undefined;
          }
        })()
      : input;

  if (!data || typeof data !== 'object') return null;
  const record = data as Record<string, unknown>;

  if (!Array.isArray(record.attributions)) return null;

  const attributions: Attribution[] = [];

  for (const raw of record.attributions) {
    if (!raw || typeof raw !== 'object') continue;
    const a = raw as Record<string, unknown>;

    if (typeof a.signer !== 'string' || typeof a.signature !== 'string') {
      continue;
    }

    attributions.push({
      signer: a.signer,
      createdAt: Number(a.created_at ?? a.createdAt ?? 0),
      signature: a.signature,
      verified: a.verified === true,
      tokens: Array.isArray(a.tokens)
        ? a.tokens.filter((t): t is string => typeof t === 'string')
        : [],
      destroy: a.destroy === true,
      genesis: a.genesis === true,
    });
  }

  return {
    subject: typeof record.subject === 'string' ? record.subject : '',
    retention: typeof record.retention === 'string' ? record.retention : '',
    attributions,
    complete: record.complete === true,
  };
}

/**
 * The attribution that signed this version, by its change token. A version
 * without a token (server bookkeeping) or whose token no retained envelope
 * carries is unattributed.
 */
export function attributionForVersion(
  version: Pick<Version, 'token' | 'message'>,
  report: HistoryAttribution | null | undefined,
): Attribution | undefined {
  const token = version.token ?? version.message;

  if (!report || !token) return undefined;

  return report.attributions.find(a => a.tokens.includes(token));
}

/**
 * Union of two reports about the same resource (server and local ClientDb),
 * de-duplicated by signature, oldest first. A verified attribution wins over
 * an unverified one for the same signature. `complete` holds only when the
 * merged set covers everything either side saw.
 */
export function mergeHistoryAttributions(
  a: HistoryAttribution | null | undefined,
  b: HistoryAttribution | null | undefined,
): HistoryAttribution | null {
  if (!a) return b ?? null;
  if (!b) return a;

  const bySignature = new Map<string, Attribution>();

  for (const attribution of [...a.attributions, ...b.attributions]) {
    const existing = bySignature.get(attribution.signature);

    if (!existing || (!existing.verified && attribution.verified)) {
      bySignature.set(attribution.signature, attribution);
    }
  }

  const attributions = [...bySignature.values()].sort(
    (x, y) => x.createdAt - y.createdAt,
  );

  return {
    subject: a.subject || b.subject,
    retention:
      a.retention === 'all' || b.retention === 'all' ? 'all' : a.retention,
    attributions,
    complete: a.complete || b.complete,
  };
}
