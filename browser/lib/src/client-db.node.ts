/**
 * Node-side ClientDb: same public surface as `ClientDbWorker`, but runs the
 * WASM module on the main thread (no Worker, no BroadcastChannel, no OPFS).
 * Uses the in-memory redb backend exposed by `ClientDb.newInMemory`.
 *
 * Intended for Node integration tests and headless harnesses. For browser
 * use, keep `ClientDbWorker`.
 */

import {
  parseHistoryAttribution,
  type HistoryAttribution,
} from './history-attribution.js';
import { readFile } from 'node:fs/promises';

import type { ClientDbQueryOpts, ClientDbQueryResult } from './client-db.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type WasmModule = any;

export interface NodeClientDbOptions {
  /** Absolute path to `atomic_wasm_bg.wasm`. */
  wasmPath: string;
  /** Path or URL to `atomic_wasm.js`. Defaults to sibling of `wasmPath`. */
  wasmJsUrl?: string;
  /** Base URL of the upstream server (e.g. `http://localhost:9883`). */
  baseUrl?: string;
}

export class NodeClientDb {
  private db: WasmModule | null = null;
  private wasm: WasmModule | null = null;
  private opts: NodeClientDbOptions;
  private ready = false;
  private seeded = true;
  private initPromise: Promise<void> | null = null;
  private seedPromise: Promise<void> | null = null;
  private _initError: Error | undefined;

  constructor(opts: NodeClientDbOptions) {
    this.opts = opts;
  }

  get initError(): Error | undefined {
    return this._initError;
  }

  get isReady(): boolean {
    return this.ready && this.seeded;
  }

  async init(baseUrl?: string): Promise<void> {
    if (this.initPromise) return this.initPromise;
    this.initPromise = this.doInit(baseUrl ?? this.opts.baseUrl);

    return this.initPromise;
  }

  private async doInit(baseUrl?: string): Promise<void> {
    try {
      const jsUrl =
        this.opts.wasmJsUrl ??
        new URL(`file://${this.opts.wasmPath.replace(/_bg\.wasm$/, '.js')}`)
          .href;
      // Dynamic import keeps bundlers from trying to resolve the WASM glue.
      this.wasm = await import(/* @vite-ignore */ jsUrl);
      const bytes = await readFile(this.opts.wasmPath);
      await this.wasm.default({ module_or_path: bytes });
      this.db = await this.wasm.ClientDb.newInMemory(baseUrl ?? null);
      await this.db.populate();
      this.ready = true;
    } catch (e) {
      this._initError = e instanceof Error ? e : new Error(String(e));
      throw this._initError;
    }
  }

  setSeedPromise(promise: Promise<void>): void {
    this.seeded = false;
    this.seedPromise = promise.then(() => {
      this.seeded = true;
    });
  }

  async waitForReady(): Promise<boolean> {
    if (this.ready && this.seeded) return true;
    if (!this.initPromise) return false;

    try {
      await this.initPromise;
      if (this.seedPromise) await this.seedPromise;

      return this.ready && this.seeded;
    } catch {
      return false;
    }
  }

  /** Mirror of {@link ClientDbWorker.isInitialized}. */
  get isInitialized(): boolean {
    return this.ready;
  }

  /** Mirror of {@link ClientDbWorker.waitForInit}. The store uses this on
   *  the cold-load path so it doesn't block on the bootstrap seed. */
  async waitForInit(): Promise<boolean> {
    if (this.ready) return true;
    if (!this.initPromise) return false;

    try {
      await this.initPromise;

      return this.ready;
    } catch {
      return false;
    }
  }

  destroy(): void {
    this.db?.free?.();
    this.db = null;
    this.wasm = null;
    this.ready = false;
    this.seeded = true;
    this.initPromise = null;
    this.seedPromise = null;
  }

  /* ------------------------------- Public API ------------------------------ */

  async getResource(subject: string): Promise<string | null> {
    const r = await this.requireDb().getResource(subject);

    return (r as string | null) ?? null;
  }

  /** Mirror of {@link ClientDbWorker.getResourceWithSnapshot} for the
   *  Node integration tests. There's no postMessage layer here, so the
   *  speedup is academic — but keeping the API symmetric means the store
   *  can use it unconditionally regardless of which backend is wired up. */
  async getResourceWithSnapshot(
    subject: string,
  ): Promise<{ jsonAd: string | null; snapshot: Uint8Array | null }> {
    const db = this.requireDb();
    const jsonAd = (await db.getResource(subject)) as string | null;
    const snapshot = jsonAd
      ? (db.getLoroSnapshot(subject) as Uint8Array | null)
      : null;

    return { jsonAd: jsonAd ?? null, snapshot: snapshot ?? null };
  }

  async putResource(jsonAd: string): Promise<void> {
    await this.requireDb().putResource(jsonAd);
  }

  /** Mirror of {@link ClientDbWorker.putResourceWithSnapshot}. */
  async putResourceWithSnapshot(
    subject: string,
    jsonAd: string,
    snapshot?: Uint8Array,
  ): Promise<void> {
    const db = this.requireDb();
    await db.putResource(jsonAd);
    if (snapshot) db.putLoroSnapshot(subject, snapshot);
  }

  /** Mirror of {@link ClientDbWorker.putResources} for the Node integration
   *  tests. No postMessage layer here, so the speedup is academic — but
   *  keeping the API symmetric means callers don't branch on which backend
   *  is wired up. */
  async putResources(jsonAds: string[]): Promise<void> {
    if (jsonAds.length === 0) return;
    const db = this.requireDb();

    for (const jsonAd of jsonAds) {
      await db.putResource(jsonAd);
    }
  }

  async applyCommit(commitJsonAd: string): Promise<void> {
    await this.requireDb().applyCommit(commitJsonAd);
  }

  async removeResource(subject: string): Promise<void> {
    await this.requireDb().removeResource(subject);
  }

  async query(opts: ClientDbQueryOpts = {}): Promise<ClientDbQueryResult> {
    const r = await this.requireDb().query(
      opts.property ?? null,
      opts.value ?? null,
      opts.sortBy ?? null,
      opts.sortDesc ?? null,
      opts.limit ?? null,
      opts.offset ?? null,
      opts.includeResources ?? null,
      opts.drive ?? null,
    );

    return r as ClientDbQueryResult;
  }

  async search(
    query: string,
    opts: {
      limit?: number;
      parents?: string | string[];
      filters?: Record<string, string | number | string[]>;
    } = {},
  ): Promise<string[]> {
    const r = this.requireDb().search(
      query,
      opts.limit ?? null,
      opts.parents ?? null,
      opts.filters ?? null,
    );

    return ((await r) as string[]) ?? [];
  }

  async allSubjects(): Promise<string[]> {
    return this.requireDb().allSubjects() as string[];
  }

  async populate(): Promise<void> {
    await this.requireDb().populate();
  }

  async exportAllResources(): Promise<string> {
    return this.requireDb().exportAllResources() as string;
  }

  async importAllResources(jsonArray: string): Promise<number> {
    return (await this.requireDb().importAllResources(jsonArray)) as number;
  }

  async getLoroSnapshot(subject: string): Promise<Uint8Array | null> {
    const r = this.requireDb().getLoroSnapshot(subject);

    return (r as Uint8Array | null) ?? null;
  }

  async historyAttribution(
    subject: string,
  ): Promise<HistoryAttribution | null> {
    const db = this.requireDb();

    if (typeof db.historyAttribution !== 'function') return null;

    return parseHistoryAttribution(await db.historyAttribution(subject));
  }

  async putBlob(hash: Uint8Array, data: Uint8Array): Promise<void> {
    this.requireDb().putBlob(hash, data);
  }

  async getBlob(hash: Uint8Array): Promise<Uint8Array | null> {
    const r = this.requireDb().getBlob(hash);

    return (r as Uint8Array | null) ?? null;
  }

  async blake3Hash(data: Uint8Array): Promise<Uint8Array> {
    // `blake3Hash` is a method on `ClientDb`, not on the wasm module. The
    // db instance gives access to it; calling it on the module fails with
    // "blake3Hash is not a function".
    return this.requireDb().blake3Hash(data) as Uint8Array;
  }

  async getAllVersionVectors(): Promise<
    Record<string, Record<string, number>>
  > {
    const r = this.requireDb().getAllVersionVectors();

    return (r as Record<string, Record<string, number>>) ?? {};
  }

  async getVersionVectorsForDrive(
    drive: string,
  ): Promise<Record<string, Record<string, number>>> {
    const r = await this.requireDb().getVersionVectorsForDrive(drive);

    return (r as Record<string, Record<string, number>>) ?? {};
  }

  private requireDb(): WasmModule {
    if (!this.db) {
      throw new Error('NodeClientDb not initialized — call init() first');
    }

    return this.db;
  }

  private requireWasm(): WasmModule {
    if (!this.wasm) {
      throw new Error('NodeClientDb not initialized — call init() first');
    }

    return this.wasm;
  }
}
