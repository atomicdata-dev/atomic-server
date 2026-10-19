/**
 * Native-side ClientDb: the `ClientDbWorker` surface, answered by the host app
 * instead of by a WASM database in this page.
 *
 * Used by the Flutter app's embedded renderer. The host (Rust `atomic_lib`)
 * is the one store on the device; this page keeps no database and opens no
 * network connection. Every call is one request over a {@link NativeChannel}:
 * `call(method, args)` resolves with the host's JSON-able answer. Bytes cross
 * the channel as base64 strings, in both directions.
 *
 * Pair it with `new Store({ connect: false })` and a {@link NativeCryptoProvider}
 * for the agent, so the page never holds the agent's secret either.
 */
import { decodeB64, encodeB64 } from './base64.js';
import type { CryptoProvider } from './CryptoProvider.js';
import {
  parseHistoryAttribution,
  type HistoryAttribution,
} from './history-attribution.js';
import type {
  ClientDbOutboxWrite,
  ClientDbQueryOpts,
  ClientDbQueryResult,
} from './client-db.js';
import { serializeDeterministically, type Commit } from './commit.js';

/** How the page talks to the host app. One request, one answer. */
export interface NativeChannel {
  call(method: string, args: unknown[]): Promise<unknown>;
}

type VersionVectors = Record<string, Record<string, number>>;

const bytes = (b64: unknown): Uint8Array | null =>
  typeof b64 === 'string' && b64 !== '' ? decodeB64(b64) : null;

export class NativeClientDb {
  /** Set when the host answered `init` with an error. */
  initError: Error | undefined;
  private ready = false;
  private initPromise: Promise<boolean> | undefined;

  constructor(private readonly channel: NativeChannel) {}

  /* ------------------------------- Lifecycle ------------------------------- */

  /** True once the host has said it is ready to answer. */
  get isReady(): boolean {
    return this.ready;
  }

  get isInitialized(): boolean {
    return this.ready;
  }

  /** Asks the host once whether its store is open. */
  waitForInit(): Promise<boolean> {
    this.initPromise ??= this.channel.call('init', []).then(
      ok => {
        this.ready = ok !== false;

        return this.ready;
      },
      e => {
        this.initError = e instanceof Error ? e : new Error(String(e));

        return false;
      },
    );

    return this.initPromise;
  }

  waitForReady(): Promise<boolean> {
    return this.waitForInit();
  }

  destroy(): void {
    this.ready = false;
  }

  /* --------------------------------- Reads --------------------------------- */

  async getResource(subject: string): Promise<string | null> {
    return (
      ((await this.channel.call('getResource', [subject])) as string | null) ??
      null
    );
  }

  async getResourceWithSnapshot(
    subject: string,
  ): Promise<{ jsonAd: string | null; snapshot: Uint8Array | null }> {
    const [one] = await this.getResourcesWithSnapshots([subject]);

    return one;
  }

  async getResourcesWithSnapshots(
    subjects: string[],
  ): Promise<Array<{ jsonAd: string | null; snapshot: Uint8Array | null }>> {
    const rows = (await this.channel.call('getResourcesWithSnapshots', [
      subjects,
    ])) as Array<{ jsonAd: string | null; snapshot: string | null }>;

    return rows.map(r => ({
      jsonAd: r.jsonAd ?? null,
      snapshot: bytes(r.snapshot),
    }));
  }

  async getLoroSnapshot(subject: string): Promise<Uint8Array | null> {
    return bytes(await this.channel.call('getLoroSnapshot', [subject]));
  }

  async query(opts: ClientDbQueryOpts = {}): Promise<ClientDbQueryResult> {
    return (await this.channel.call('query', [opts])) as ClientDbQueryResult;
  }

  async search(
    query: string,
    opts: {
      limit?: number;
      parents?: string | string[];
      filters?: Record<string, string | number | string[]>;
      includeTrashed?: boolean;
    } = {},
  ): Promise<string[]> {
    return (
      ((await this.channel.call('search', [query, opts])) as string[] | null) ??
      []
    );
  }

  async allSubjects(): Promise<string[]> {
    return (await this.channel.call('allSubjects', [])) as string[];
  }

  async getDriveSubjects(drive: string): Promise<string[]> {
    return (await this.channel.call('getDriveSubjects', [drive])) as string[];
  }

  async getAllVersionVectors(): Promise<VersionVectors> {
    return (await this.channel.call(
      'getAllVersionVectors',
      [],
    )) as VersionVectors;
  }

  async getVersionVectorsForDrive(drive: string): Promise<VersionVectors> {
    return (await this.channel.call('getVersionVectorsForDrive', [
      drive,
    ])) as VersionVectors;
  }

  async getVersionVectorsForSubjects(
    subjects: string[],
  ): Promise<VersionVectors> {
    return (await this.channel.call('getVersionVectorsForSubjects', [
      subjects,
    ])) as VersionVectors;
  }

  async historyAttribution(
    subject: string,
  ): Promise<HistoryAttribution | null> {
    const raw = await this.channel.call('historyAttribution', [subject]);

    return typeof raw === 'string' ? parseHistoryAttribution(raw) : null;
  }

  async getBlob(hash: Uint8Array): Promise<Uint8Array | null> {
    return bytes(await this.channel.call('getBlob', [encodeB64(hash)]));
  }

  /* --------------------------------- Writes -------------------------------- */

  async flush(): Promise<void> {
    await this.channel.call('flush', []);
  }

  async putResource(jsonAd: string): Promise<void> {
    await this.channel.call('putResource', [jsonAd]);
  }

  async putResources(jsonAds: string[]): Promise<void> {
    await this.channel.call('putResources', [jsonAds]);
  }

  async putResourceWithSnapshot(
    subject: string,
    jsonAd: string,
    snapshot?: Uint8Array,
    outbox?: ClientDbOutboxWrite,
  ): Promise<void> {
    await this.channel.call('putResourceWithSnapshot', [
      subject,
      jsonAd,
      snapshot ? encodeB64(snapshot) : null,
      outbox ?? null,
    ]);
  }

  /** A commit this device signed: the host applies it and queues it. */
  async applyCommit(commitJsonAd: string): Promise<void> {
    await this.channel.call('applyCommit', [commitJsonAd]);
  }

  /**
   * The page's commit transport (`Store.setCommitTransport`): every commit
   * the store would send to a server goes to the host instead, in the body
   * `Client.postCommit` would post. The host applies it to its store and
   * queues it for the server and peers; the commit is stored once that call
   * answers. Without it, a page with `connect: false` saves only offline,
   * into a database the host does not keep.
   */
  readonly commitTransport = async (commit: Commit): Promise<Commit> => {
    await this.applyCommit(serializeDeterministically({ ...commit }, true));

    return commit;
  };

  /** A commit that came from elsewhere. */
  async applyPeerCommit(commitJsonAd: string): Promise<void> {
    await this.channel.call('applyPeerCommit', [commitJsonAd]);
  }

  async removeResource(subject: string): Promise<void> {
    await this.channel.call('removeResource', [subject]);
  }

  async putBlob(hash: Uint8Array, data: Uint8Array): Promise<void> {
    await this.channel.call('putBlob', [encodeB64(hash), encodeB64(data)]);
  }

  async outboxEntries(agent: string): Promise<string[]> {
    return (await this.channel.call('outboxEntries', [agent])) as string[];
  }

  async outboxWrite(
    write: ClientDbOutboxWrite,
    durable: boolean,
  ): Promise<void> {
    await this.channel.call('outboxWrite', [write, durable]);
  }
}

/**
 * An agent's signing, done by the host. The page holds only the public key;
 * the secret never enters it. `signsDeterministically` is true: the host signs
 * with Ed25519 (RFC 8032), and the private drive's DID is derived from a
 * signature.
 */
export class NativeCryptoProvider implements CryptoProvider {
  readonly type = 'native';
  readonly signsDeterministically = true;
  private publicKey: Promise<string> | undefined;

  constructor(private readonly channel: NativeChannel) {}

  /** Signs a UTF-8 string; the host answers base64url, no padding. */
  async sign(data: string): Promise<string> {
    return (await this.channel.call('sign', [data])) as string;
  }

  async signBytes(data: Uint8Array): Promise<string> {
    return (await this.channel.call('signBytes', [encodeB64(data)])) as string;
  }

  getPublicKey(): Promise<string> {
    this.publicKey ??= this.channel.call('publicKey', []).then(String);

    return this.publicKey;
  }
}
