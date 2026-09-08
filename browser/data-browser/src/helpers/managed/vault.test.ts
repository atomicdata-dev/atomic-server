import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  agentVaultProof,
  enrollVault,
  vaultLaneId,
  backupDrive,
  restoreDrive,
  setUpVaultForDrive,
  recoverDriveKey,
  nextSegmentFor,
  runVaultBackup,
  type VaultCapableDb,
  type VaultKeyOps,
  type VaultDriveState,
} from './vault';

/**
 * These cover the orchestration, which is deliberately the half that lives in
 * TypeScript: WASM does crypto and format, this does the network. The Rust
 * tests cannot reach any of it — ordering of upload vs confirm, what happens
 * when storage rejects a PUT, whether restore replays segments in the right
 * order. Each of those is a data-integrity property, not a plumbing detail.
 */

it('sends name and emoji as optional enrollment metadata', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    new Response(JSON.stringify({ enrollment: { id: '1' } }), {
      status: 200,
    }),
  );
  await enrollVault('did:ad:drive', 'did:ad:agent:test', {
    name: 'Design',
    emoji: '🎨',
  });
  expect(JSON.parse(String(fetch.mock.calls[0][1]?.body))).toEqual({
    drive_subject: 'did:ad:drive',
    agent_subject: 'did:ad:agent:test',
    drive_name: 'Design',
    drive_emoji: '🎨',
  });
});

const DEVICE = '03'.repeat(32);
const PSEUDONYM = 'testpseudonym';
const KEY = new Uint8Array(32).fill(7);

beforeEach(() => {
  vi.stubEnv('VITE_MANAGED_PORTAL_URL', 'https://control.test');
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

/** A sealed delta pack, as the WASM binding would hand it over. */
function sealedPack(objectKey: string, bytes = 4) {
  return {
    objectKey,
    sealed: new Uint8Array(bytes).fill(1),
    kind: 'pack' as const,
    resources: 3,
    unchanged: 17,
    tombstones: 0,
    coverage: {},
  };
}

/** A sealed checkpoint — self-sufficient, and published after it is confirmed. */
function sealedCheckpoint(
  objectKey: string,
  coverage: Record<string, number> = {},
) {
  return {
    objectKey,
    sealed: new Uint8Array(8).fill(2),
    kind: 'checkpoint' as const,
    resources: 20,
    unchanged: 0,
    tombstones: 0,
    coverage,
  };
}

const PACK_KEY = `vault/${PSEUDONYM}/lanes/${DEVICE}/seg-000001.pack`;
const CKPT_KEY = `vault/${PSEUDONYM}/checkpoints/ckpt-000001.loro`;

/** The arguments every `backupDrive` call needs, minus what a test varies. */
const PASS = {
  driveSubject: 'did:ad:drive',
  drivePseudonym: PSEUDONYM,
  devicePubkey: DEVICE,
  driveKey: KEY,
  segment: 1,
  checkpointN: 1,
  driveHasCheckpoint: true,
  observedLanes: {},
};

/** Records every request so a test can assert on order, not just on calls. */
function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  const calls: { url: string; method: string }[] = [];
  const spy = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, method: init?.method ?? 'GET' });
    const result = handler(url, init);

    return (
      result ?? {
        ok: true,
        status: 200,
        json: async () => ({}),
      }
    );
  });
  vi.stubGlobal('fetch', spy);

  return calls;
}

describe('backupDrive', () => {
  it('uploads nothing when the drive has not changed', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => null),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    const calls = mockFetch(() => undefined);

    const outcome = await backupDrive({ db, ...PASS });

    expect(outcome).toEqual({ status: 'nothing-to-do' });
    expect(calls).toHaveLength(0);
  });

  /**
   * The object is confirmed only after storage accepted it. Confirming first
   * would make quota drift upward on every dropped connection — usage the user
   * never consumed and cannot clear.
   */
  it('does not upload or advance the backup cursor after cancellation during export', async () => {
    const controller = new AbortController();
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => {
        controller.abort();

        return sealedPack(PACK_KEY);
      }),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    const calls = mockFetch(() => undefined);
    await expect(
      backupDrive({ db, ...PASS, signal: controller.signal }),
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(calls).toHaveLength(0);
    expect(db.vaultCommitSegment).not.toHaveBeenCalled();
  });

  it('re-exports under a fresh checkpoint number when a confirmed object already occupies it', async () => {
    const secondKey = CKPT_KEY.replace('000001', '000002');
    const db: VaultCapableDb = {
      vaultExport: vi
        .fn()
        .mockResolvedValueOnce(sealedCheckpoint(CKPT_KEY))
        .mockResolvedValueOnce(sealedCheckpoint(secondKey)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    let request = 0;
    const calls = mockFetch(url => {
      if (url.endsWith('/upload-urls')) {
        const occupied = request++ === 0;

        return {
          ok: true,
          json: async () => ({
            uploads: [
              {
                object_id: occupied ? 'old' : 'new',
                object_key: occupied ? CKPT_KEY : secondKey,
                already_stored: occupied,
                url: occupied ? '' : 'https://s3.test/new',
                headers: [],
                size_bytes: 8,
              },
            ],
          }),
        };
      }
    });
    expect(
      await backupDrive({ db, ...PASS, driveHasCheckpoint: false }),
    ).toMatchObject({ status: 'backed-up', objectKey: secondKey });
    expect(
      calls.filter(call => call.method === 'PUT').map(call => call.url),
    ).toEqual(['https://s3.test/new']);
    expect(db.vaultExport).toHaveBeenCalledTimes(2);
    expect(db.vaultCommitSegment).toHaveBeenCalledTimes(1);
  });

  it('confirms only after storage accepts the bytes', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => sealedPack(PACK_KEY)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    const calls = mockFetch(url => {
      if (url.endsWith('/upload-urls')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            uploads: [
              {
                object_id: 'obj-1',
                object_key: PACK_KEY,
                url: 'https://s3.test/put',
                method: 'PUT',
                headers: [['content-length', '4']],
                size_bytes: 4,
              },
            ],
          }),
        };
      }

      return undefined;
    });

    const outcome = await backupDrive({ db, ...PASS });

    expect(outcome).toMatchObject({ status: 'backed-up', resources: 3 });
    const order = calls.map(c => c.url);
    expect(order[0]).toContain('/upload-urls');
    expect(order[1]).toBe('https://s3.test/put');
    expect(order[2]).toContain('/confirm-upload');
  });

  it('does not confirm an upload storage rejected', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => sealedPack(PACK_KEY)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    const calls = mockFetch(url => {
      if (url.endsWith('/upload-urls')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            uploads: [
              {
                object_id: 'obj-1',
                object_key: PACK_KEY,
                url: 'https://s3.test/put',
                method: 'PUT',
                headers: [],
                size_bytes: 4,
              },
            ],
          }),
        };
      }

      if (url === 'https://s3.test/put') {
        return { ok: false, status: 403, json: async () => ({}) };
      }

      return undefined;
    });

    await expect(backupDrive({ db, ...PASS })).rejects.toThrow(
      /upload failed/i,
    );

    expect(calls.some(c => c.url.includes('/confirm-upload'))).toBe(false);
  });

  /**
   * A checkpoint has one step a delta does not: publishing. Until that lands
   * the control plane holds an anchor it does not know it may prune against, so
   * the pass costs storage and frees none — the exact shape of "reported
   * success without doing the work" this feature keeps producing.
   */
  it('publishes a checkpoint after confirming it, with its coverage', async () => {
    const coverage = { [DEVICE]: 4 };
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => sealedCheckpoint(CKPT_KEY, coverage)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    const bodies: Record<string, unknown> = {};
    const calls = mockFetch((url, init) => {
      // Keyed by endpoint rather than full URL: the control-plane base comes
      // from an env var, and pinning it here would make this test about
      // configuration instead of about the checkpoint protocol.
      //
      // The PUT carries raw ciphertext, not JSON — only control-plane calls
      // send a string body.
      if (typeof init?.body === 'string') {
        bodies[url.split('/').pop()!] = JSON.parse(init.body);
      }

      if (url.endsWith('/upload-urls')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            uploads: [
              {
                object_id: 'ckpt-obj',
                object_key: CKPT_KEY,
                url: 'https://s3.test/put',
                method: 'PUT',
                headers: [],
                size_bytes: 8,
              },
            ],
          }),
        };
      }

      return undefined;
    });

    const outcome = await backupDrive({
      db,
      ...PASS,
      driveHasCheckpoint: false,
      checkpointN: 3,
    });

    expect(outcome).toMatchObject({ status: 'backed-up', kind: 'checkpoint' });

    // Upload declares the checkpoint kind, not a lane pack — a checkpoint
    // uploaded as a pack would land in a lane and never become an anchor.
    const uploadBody = bodies['upload-urls'] as {
      objects: { kind: string; checkpoint_n: number }[];
    };
    expect(uploadBody.objects[0].kind).toBe('checkpoint');
    expect(uploadBody.objects[0].checkpoint_n).toBe(3);

    const order = calls.map(c => c.url);
    expect(order[0]).toContain('/upload-urls');
    expect(order[1]).toBe('https://s3.test/put');
    expect(order[2]).toContain('/confirm-upload');
    expect(order[3]).toContain('/checkpoint');

    expect(bodies['checkpoint']).toMatchObject({ checkpoint_n: 3, coverage });
  });

  /**
   * Two devices over an anchorless vault both pick the same number, and the
   * server rejects the loser. Its object is already stored and just as valid as
   * the winner's, so the pass still counts — failing it would leave the lane
   * cursor uncommitted and re-ship everything next tick.
   */
  it('still counts the pass when another device published that checkpoint first', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => sealedCheckpoint(CKPT_KEY)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url => {
      if (url.endsWith('/upload-urls')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            uploads: [
              {
                object_id: 'ckpt-obj',
                object_key: CKPT_KEY,
                url: 'https://s3.test/put',
                method: 'PUT',
                headers: [],
                size_bytes: 8,
              },
            ],
          }),
        };
      }

      if (url.endsWith('/checkpoint')) {
        return {
          ok: false,
          status: 409,
          json: async () => ({ error: 'checkpoint 1 is already published' }),
        };
      }

      return undefined;
    });

    const outcome = await backupDrive({ db, ...PASS });

    expect(outcome).toMatchObject({ status: 'backed-up' });
    expect(db.vaultCommitSegment).toHaveBeenCalled();
  });

  /**
   * The lane cursor is only advanced after the object is durably stored. That
   * mattered before; it matters more now that a pass ships deltas, because a
   * cursor advanced past an object that never landed leaves ops no later delta
   * would ever ship again.
   */
  it('does not commit the lane when the upload never landed', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => sealedPack(PACK_KEY)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url => {
      if (url.endsWith('/upload-urls')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            uploads: [
              {
                object_id: 'obj-1',
                object_key: PACK_KEY,
                url: 'https://s3.test/put',
                method: 'PUT',
                headers: [],
                size_bytes: 4,
              },
            ],
          }),
        };
      }

      if (url === 'https://s3.test/put') {
        return { ok: false, status: 500, json: async () => ({}) };
      }

      return undefined;
    });

    await expect(backupDrive({ db, ...PASS })).rejects.toThrow();
    expect(db.vaultCommitSegment).not.toHaveBeenCalled();
  });

  /**
   * The layout is implemented in two repos. If they disagree, the upload lands
   * where restore never looks, and nothing notices until a restore comes up
   * short — so it has to be caught at the moment of disagreement.
   */
  it('refuses to upload when the server names a different object key', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => sealedPack(PACK_KEY)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url => {
      if (url.endsWith('/upload-urls')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            uploads: [
              {
                object_id: 'obj-1',
                object_key: `vault/${PSEUDONYM}/lanes/${DEVICE}/seg-000009.pack`,
                url: 'https://s3.test/put',
                method: 'PUT',
                headers: [],
                size_bytes: 4,
              },
            ],
          }),
        };
      }

      return undefined;
    });

    await expect(backupDrive({ db, ...PASS })).rejects.toThrow(/key mismatch/i);
  });

  /** Assigning Content-Length throws in the browser before the request goes out. */
  it('strips content-length from the headers it forwards', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => sealedPack(PACK_KEY)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    let putHeaders: Record<string, string> | undefined;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.endsWith('/upload-urls')) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              uploads: [
                {
                  object_id: 'obj-1',
                  object_key: PACK_KEY,
                  url: 'https://s3.test/put',
                  method: 'PUT',
                  headers: [
                    ['content-length', '4'],
                    ['x-custom', 'kept'],
                  ],
                  size_bytes: 4,
                },
              ],
            }),
          };
        }

        if (url === 'https://s3.test/put') {
          putHeaders = init?.headers as Record<string, string>;
        }

        return { ok: true, status: 200, json: async () => ({}) };
      }),
    );

    await backupDrive({ db, ...PASS });

    expect(putHeaders).toEqual({ 'x-custom': 'kept' });
  });

  /** A billing rejection should read as one, not as a generic failure. */
  it("surfaces the control plane's own message", async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => sealedPack(PACK_KEY)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url =>
      url.endsWith('/upload-urls')
        ? {
            ok: false,
            status: 402,
            json: async () => ({ error: 'Cloud Vault quota exceeded' }),
          }
        : undefined,
    );

    await expect(backupDrive({ db, ...PASS })).rejects.toThrow(
      'Cloud Vault quota exceeded',
    );
  });
});

describe('restoreDrive', () => {
  it('reports nothing when the vault is empty', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url =>
      url.endsWith('/objects')
        ? { ok: true, status: 200, json: async () => [] }
        : undefined,
    );

    const outcome = await restoreDrive({
      db,
      drivePseudonym: PSEUDONYM,
      devicePubkey: DEVICE,
      driveKey: KEY,
    });

    expect(outcome.resourcesRestored).toBe(0);
    expect(db.vaultImport).not.toHaveBeenCalled();
  });

  /**
   * The listing is ordered for replay; `download-urls` answers per request and
   * is not required to echo that order. Applying out of order would let a later
   * segment's deletion land before the pack that re-creates the resource — the
   * delete would silently be undone.
   */
  it('applies objects in listing order, not download order', async () => {
    const first = `vault/${PSEUDONYM}/lanes/${DEVICE}/seg-000001.pack`;
    const second = `vault/${PSEUDONYM}/lanes/${DEVICE}/seg-000002.pack`;
    const imported: string[] = [];

    const db: VaultCapableDb = {
      vaultExport: vi.fn(),
      vaultImport: vi.fn(
        async (
          _k: Uint8Array,
          _e: number,
          _p: string,
          _d: string,
          objects: { objectKey: string; sealed: Uint8Array }[],
        ) => {
          imported.push(...objects.map(o => o.objectKey));

          return {
            packsRead: 2,
            resourcesRestored: 5,
            tombstonesApplied: 1,
            objectsSkipped: 0,
            objectsUnreadable: 0,
          };
        },
      ),
      vaultCommitSegment: vi.fn(),
    };

    mockFetch(url => {
      if (url.endsWith('/objects')) {
        return {
          ok: true,
          status: 200,
          json: async () => [
            { object_id: 'a', object_key: first },
            { object_id: 'b', object_key: second },
          ],
        };
      }

      if (url.endsWith('/download-urls')) {
        // Deliberately reversed.
        return {
          ok: true,
          status: 200,
          json: async () => ({
            downloads: [
              { object_id: 'b', object_key: second, url: 'https://s3.test/2' },
              { object_id: 'a', object_key: first, url: 'https://s3.test/1' },
            ],
          }),
        };
      }

      return {
        ok: true,
        status: 200,
        arrayBuffer: async () => new Uint8Array([1, 2]).buffer,
      };
    });

    const outcome = await restoreDrive({
      db,
      drivePseudonym: PSEUDONYM,
      devicePubkey: DEVICE,
      driveKey: KEY,
    });

    expect(imported).toEqual([first, second]);
    expect(outcome.resourcesRestored).toBe(5);
  });

  it('reports progress as objects arrive', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(),
      vaultImport: vi.fn(async () => ({
        packsRead: 2,
        resourcesRestored: 1,
        tombstonesApplied: 0,
        objectsSkipped: 0,
        objectsUnreadable: 0,
      })),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url => {
      if (url.endsWith('/objects')) {
        return {
          ok: true,
          status: 200,
          json: async () => [
            { object_id: 'a', object_key: 'k1' },
            { object_id: 'b', object_key: 'k2' },
          ],
        };
      }

      if (url.endsWith('/download-urls')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            downloads: [
              { object_id: 'a', object_key: 'k1', url: 'https://s3.test/1' },
              { object_id: 'b', object_key: 'k2', url: 'https://s3.test/2' },
            ],
          }),
        };
      }

      return {
        ok: true,
        status: 200,
        arrayBuffer: async () => new Uint8Array([9]).buffer,
      };
    });

    const seen: [number, number][] = [];
    await restoreDrive({
      db,
      drivePseudonym: PSEUDONYM,
      devicePubkey: DEVICE,
      driveKey: KEY,
      onProgress: (done, total) => seen.push([done, total]),
    });

    expect(seen).toEqual([
      [1, 2],
      [2, 2],
    ]);
  });

  it('fails loudly when the server issues no URL for a listed object', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url => {
      if (url.endsWith('/objects')) {
        return {
          ok: true,
          status: 200,
          json: async () => [{ object_id: 'a', object_key: 'k1' }],
        };
      }

      if (url.endsWith('/download-urls')) {
        return { ok: true, status: 200, json: async () => ({ downloads: [] }) };
      }

      return undefined;
    });

    await expect(
      restoreDrive({
        db,
        drivePseudonym: PSEUDONYM,
        devicePubkey: DEVICE,
        driveKey: KEY,
      }),
    ).rejects.toThrow(/No download URL/i);
  });
});

describe('key management', () => {
  /** A stand-in for the WASM key ops: wrapping is reversible and keyed. */
  function fakeKeys(): VaultKeyOps {
    let counter = 0;

    return {
      vaultGenerateKey: () => new Uint8Array(32).fill(++counter),
      vaultWrapKey: (key, secret) =>
        JSON.stringify({ key: Array.from(key), secret: Array.from(secret) }),
      vaultUnwrapKey: (envelope, secret) => {
        const parsed = JSON.parse(envelope);

        if (parsed.secret.join() !== Array.from(secret).join()) {
          throw new Error('wrong agent secret');
        }

        return new Uint8Array(parsed.key);
      },
    };
  }

  const AGENT_SECRET = new Uint8Array([1, 2, 3]);

  /**
   * The failure this guards against is unrecoverable: a second key would leave
   * every object written under the first permanently unreadable.
   */
  it('does not fetch a key if sign-out cancels enrollment', async () => {
    const controller = new AbortController();
    const calls = mockFetch(url => {
      if (url.endsWith('/enroll')) {
        controller.abort();

        return {
          ok: true,
          status: 200,
          json: async () => ({ enrollment: { drive_pseudonym: PSEUDONYM } }),
        };
      }

      return { ok: true, status: 204 };
    });

    await expect(
      setUpVaultForDrive({
        keys: fakeKeys(),
        driveSubject: 'did:ad:drive',
        agentSubject: 'did:ad:agent:x',
        agentSecret: AGENT_SECRET,
        signal: controller.signal,
      }),
    ).rejects.toThrow();
    expect(calls.map(call => call.url)).toHaveLength(1);
  });

  it('reuses an existing key rather than minting a second one', async () => {
    const keys = fakeKeys();
    const stored = keys.vaultWrapKey(new Uint8Array(32).fill(99), AGENT_SECRET);
    const puts: string[] = [];

    mockFetch((url, init) => {
      if (url.endsWith('/enroll')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            enrollment: { drive_pseudonym: PSEUDONYM, id: 'e1' },
          }),
        };
      }

      if (url.endsWith('/key') && init?.method === 'PUT') {
        puts.push(String(init.body));

        return { ok: true, status: 200, json: async () => ({}) };
      }

      if (url.endsWith('/key')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ envelope: stored }),
        };
      }

      return undefined;
    });

    const { driveKey } = await setUpVaultForDrive({
      keys,
      driveSubject: 'did:ad:drive',
      agentSubject: 'did:ad:agent:x',
      agentSecret: AGENT_SECRET,
    });

    expect(Array.from(driveKey)).toEqual(
      Array.from(new Uint8Array(32).fill(99)),
    );
    expect(puts).toHaveLength(0);
  });

  it('stores the wrapped key before anything is backed up', async () => {
    const keys = fakeKeys();
    const puts: string[] = [];

    mockFetch((url, init) => {
      if (url.endsWith('/enroll')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            enrollment: { drive_pseudonym: PSEUDONYM, id: 'e1' },
          }),
        };
      }

      if (url.endsWith('/key') && init?.method === 'PUT') {
        puts.push(String(init.body));

        return { ok: true, status: 200, json: async () => ({}) };
      }

      // No key stored yet.
      if (url.endsWith('/key')) return { ok: true, status: 204 };

      return undefined;
    });

    const { driveKey } = await setUpVaultForDrive({
      keys,
      driveSubject: 'did:ad:drive',
      agentSubject: 'did:ad:agent:x',
      agentSecret: AGENT_SECRET,
    });

    expect(puts).toHaveLength(1);
    // The wrapped form must actually contain this key, or restore gets a
    // different one back.
    expect(
      keys.vaultUnwrapKey(JSON.parse(puts[0]).envelope, AGENT_SECRET),
    ).toEqual(driveKey);
  });

  /** The wiped-device path, end to end through the client. */
  it('recovers a key from the control plane with only the agent secret', async () => {
    const keys = fakeKeys();
    const original = new Uint8Array(32).fill(7);
    const envelope = keys.vaultWrapKey(original, AGENT_SECRET);

    mockFetch(url =>
      url.endsWith('/key')
        ? { ok: true, status: 200, json: async () => ({ envelope }) }
        : undefined,
    );

    const recovered = await recoverDriveKey({
      keys,
      drivePseudonym: PSEUDONYM,
      agentSecret: AGENT_SECRET,
    });

    expect(Array.from(recovered.driveKey)).toEqual(Array.from(original));
    // A control plane predating epoch tracking sends no `key_epoch`; that is
    // epoch 1, the only one any drive had.
    expect(recovered.keyEpoch).toBe(1);
  });

  /**
   * Two clients enrolling the same drive at once would each mint a key and race
   * to store it. The server is create-only, so the loser must adopt the
   * winner's key — anything else leaves one client's backups undecryptable by
   * the other.
   */
  it("adopts the winner's key when another client stored one first", async () => {
    const keys = fakeKeys();
    const winnersKey = new Uint8Array(32).fill(42);
    const stored = keys.vaultWrapKey(winnersKey, AGENT_SECRET);
    let sawPut = false;

    mockFetch((url, init) => {
      if (url.endsWith('/enroll')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            enrollment: { drive_pseudonym: PSEUDONYM, id: 'e1' },
          }),
        };
      }

      if (url.endsWith('/key') && init?.method === 'PUT') {
        sawPut = true;

        // Create-only: the other client got there first.
        return {
          ok: false,
          status: 409,
          json: async () => ({ error: 'a key envelope already exists' }),
        };
      }

      if (url.endsWith('/key')) {
        // First read: nothing yet. Second read (after the conflict): the winner.
        return sawPut
          ? { ok: true, status: 200, json: async () => ({ envelope: stored }) }
          : { ok: true, status: 204 };
      }

      return undefined;
    });

    const { driveKey } = await setUpVaultForDrive({
      keys,
      driveSubject: 'did:ad:drive',
      agentSubject: 'did:ad:agent:x',
      agentSecret: AGENT_SECRET,
    });

    expect(Array.from(driveKey)).toEqual(Array.from(winnersKey));
  });

  /**
   * A present-but-unusable envelope must not read as "no key yet" — the caller
   * would mint a second key and overwrite the real one, making every existing
   * backup undecryptable.
   */
  it('refuses a malformed stored envelope rather than treating it as absent', async () => {
    mockFetch(url =>
      url.endsWith('/key')
        ? { ok: true, status: 200, json: async () => ({ envelope: '' }) }
        : undefined,
    );

    await expect(
      recoverDriveKey({
        keys: fakeKeys(),
        drivePseudonym: PSEUDONYM,
        agentSecret: AGENT_SECRET,
      }),
    ).rejects.toThrow(/malformed/i);
  });

  it('says so plainly when a drive has no stored key', async () => {
    mockFetch(url =>
      url.endsWith('/key') ? { ok: true, status: 204 } : undefined,
    );

    await expect(
      recoverDriveKey({
        keys: fakeKeys(),
        drivePseudonym: PSEUDONYM,
        agentSecret: AGENT_SECRET,
      }),
    ).rejects.toThrow(/no stored vault key/i);
  });
});

describe('lane bookkeeping', () => {
  /**
   * Sealing parks the lane's progress; only a confirmed upload makes it
   * official. Committing earlier would let a failed upload convince the next
   * pass that a segment exists in the vault when it does not.
   */
  it('commits the segment only after the upload is confirmed', async () => {
    const order: string[] = [];
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => sealedPack(PACK_KEY)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(() => {
        order.push('commit');
      }),
    };
    mockFetch(url => {
      if (url.endsWith('/upload-urls')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            uploads: [
              {
                object_id: 'obj-1',
                object_key: PACK_KEY,
                url: 'https://s3.test/put',
                method: 'PUT',
                headers: [],
                size_bytes: 4,
              },
            ],
          }),
        };
      }

      if (url.endsWith('/confirm-upload')) order.push('confirm');

      if (url === 'https://s3.test/put') order.push('put');

      return undefined;
    });

    await backupDrive({ db, ...PASS, segment: 3 });

    expect(order).toEqual(['put', 'confirm', 'commit']);
    expect(db.vaultCommitSegment).toHaveBeenCalledWith(PSEUDONYM, DEVICE, 3);
  });

  it('does not commit a segment whose upload failed', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => sealedPack(PACK_KEY)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url => {
      if (url.endsWith('/upload-urls')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            uploads: [
              {
                object_id: 'obj-1',
                object_key: PACK_KEY,
                url: 'https://s3.test/put',
                method: 'PUT',
                headers: [],
                size_bytes: 4,
              },
            ],
          }),
        };
      }

      if (url === 'https://s3.test/put') {
        return { ok: false, status: 500, json: async () => ({}) };
      }

      return undefined;
    });

    await expect(backupDrive({ db, ...PASS, segment: 3 })).rejects.toThrow();

    expect(db.vaultCommitSegment).not.toHaveBeenCalled();
  });

  it('reports a missing upload URL rather than crashing on undefined', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => sealedPack(PACK_KEY)),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url =>
      url.endsWith('/upload-urls')
        ? { ok: true, status: 200, json: async () => ({ uploads: [] }) }
        : undefined,
    );

    await expect(backupDrive({ db, ...PASS })).rejects.toThrow(
      /no upload URL/i,
    );
  });
});

describe('scheduling', () => {
  function state(
    lanes: Record<string, number>,
    status = 'active',
    keyEpoch?: number,
  ): VaultDriveState {
    return {
      enrollment: {
        id: 'e1',
        drive_subject: 'did:ad:drive',
        drive_pseudonym: PSEUDONYM,
        status,
        used_bytes: 0,
        quota_bytes: 100,
        last_backup_at: null,
        ...(keyEpoch === undefined ? {} : { key_epoch: keyEpoch }),
      },
      lanes,
      checkpoints: [],
      pending_uploads: 0,
      confirmed_objects: 0,
    };
  }

  it('starts at segment 1 on a lane that has never been written', () => {
    expect(nextSegmentFor(state({}), DEVICE)).toBe(1);
  });

  /**
   * Taken from the server, not from memory: a device that cleared its storage
   * would otherwise restart at 1 and overwrite a pack that is still the only
   * copy of some history.
   */
  it('continues after the last segment the server saw', () => {
    expect(nextSegmentFor(state({ [DEVICE]: 7 }), DEVICE)).toBe(8);
  });

  it('numbers each device lane independently', () => {
    const other = 'ff'.repeat(32);
    expect(nextSegmentFor(state({ [other]: 9 }), DEVICE)).toBe(1);
  });

  /**
   * Two passes at once would both read the same "next" segment and race to
   * write it; the loser's history would be silently overwritten.
   */
  it('runs one pass at a time per drive', async () => {
    let exports = 0;
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => {
        exports += 1;
        await new Promise(resolve => setTimeout(resolve, 10));

        return null;
      }),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url =>
      url.endsWith('/state')
        ? { ok: true, status: 200, json: async () => state({}) }
        : undefined,
    );

    const args = {
      db,
      driveSubject: 'did:ad:drive',
      drivePseudonym: PSEUDONYM,
      devicePubkey: DEVICE,
      driveKey: KEY,
    };
    const [a, b] = await Promise.all([
      runVaultBackup(args),
      runVaultBackup(args),
    ]);

    expect(exports).toBe(1);
    expect(a).toBe(b);
  });

  it('allows a fresh pass once the previous one finished', async () => {
    let exports = 0;
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => {
        exports += 1;

        return null;
      }),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url =>
      url.endsWith('/state')
        ? { ok: true, status: 200, json: async () => state({}) }
        : undefined,
    );

    const args = {
      db,
      driveSubject: 'did:ad:drive',
      drivePseudonym: PSEUDONYM,
      devicePubkey: DEVICE,
      driveKey: KEY,
    };
    await runVaultBackup(args);
    await runVaultBackup(args);

    expect(exports).toBe(2);
  });

  /** A suspended vault refuses uploads; asking every tick just buries the log. */
  it('does not attempt a backup while the vault is suspended', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url =>
      url.endsWith('/state')
        ? { ok: true, status: 200, json: async () => state({}, 'suspended') }
        : undefined,
    );

    const outcome = await runVaultBackup({
      db,
      driveSubject: 'did:ad:drive',
      drivePseudonym: PSEUDONYM,
      devicePubkey: DEVICE,
      driveKey: KEY,
    });

    expect(outcome).toEqual({ status: 'nothing-to-do' });
    expect(db.vaultExport).not.toHaveBeenCalled();
  });

  /**
   * After a re-key elsewhere, the cached key is for an epoch the server no
   * longer accepts. Declaring the new epoch while sealing with the old key
   * would pass the server's check and leave objects the new key cannot read,
   * so the key must be refreshed first and the export sealed with it.
   */
  it('refreshes the key when the drive reports a newer epoch', async () => {
    const FRESH = new Uint8Array(32).fill(9);
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => null),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url =>
      url.endsWith('/state')
        ? { ok: true, status: 200, json: async () => state({}, 'active', 2) }
        : undefined,
    );
    const refreshDriveKey = vi.fn(async () => ({
      driveKey: FRESH,
      keyEpoch: 2,
    }));

    await runVaultBackup({
      db,
      driveSubject: 'did:ad:drive',
      drivePseudonym: PSEUDONYM,
      devicePubkey: DEVICE,
      driveKey: KEY,
      driveKeyEpoch: 1,
      refreshDriveKey,
    });

    expect(refreshDriveKey).toHaveBeenCalledTimes(1);
    const [, keyUsed, epochUsed] = (db.vaultExport as ReturnType<typeof vi.fn>)
      .mock.calls[0];
    expect(keyUsed).toBe(FRESH);
    expect(epochUsed).toBe(2);
  });

  it('does not seal anything when a re-keyed drive cannot be refreshed', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => null),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url =>
      url.endsWith('/state')
        ? { ok: true, status: 200, json: async () => state({}, 'active', 2) }
        : undefined,
    );

    await expect(
      runVaultBackup({
        db,
        driveSubject: 'did:ad:drive',
        drivePseudonym: PSEUDONYM,
        devicePubkey: DEVICE,
        driveKey: KEY,
        driveKeyEpoch: 1,
      }),
    ).rejects.toThrow(/re-keyed/);
    expect(db.vaultExport).not.toHaveBeenCalled();

    // A refresh that still does not reach the drive's epoch is refused too:
    // the envelope and the enrollment disagree, and neither is safe to trust.
    await expect(
      runVaultBackup({
        db,
        driveSubject: 'did:ad:drive',
        drivePseudonym: PSEUDONYM,
        devicePubkey: DEVICE,
        driveKey: KEY,
        driveKeyEpoch: 1,
        refreshDriveKey: async () => ({ driveKey: KEY, keyEpoch: 1 }),
      }),
    ).rejects.toThrow(/epoch 1/);
    expect(db.vaultExport).not.toHaveBeenCalled();
  });

  /** A drive that was never re-keyed is at epoch 1, which is what a caller
   *  without an epoch is assumed to hold: no refresh, no error. */
  it('accepts a caller without an epoch on a drive still at epoch 1', async () => {
    const db: VaultCapableDb = {
      vaultExport: vi.fn(async () => null),
      vaultImport: vi.fn(),
      vaultCommitSegment: vi.fn(),
    };
    mockFetch(url =>
      url.endsWith('/state')
        ? { ok: true, status: 200, json: async () => state({}) }
        : undefined,
    );
    const refreshDriveKey = vi.fn();

    await runVaultBackup({
      db,
      driveSubject: 'did:ad:drive',
      drivePseudonym: PSEUDONYM,
      devicePubkey: DEVICE,
      driveKey: KEY,
      refreshDriveKey,
    });

    expect(refreshDriveKey).not.toHaveBeenCalled();
    expect((db.vaultExport as ReturnType<typeof vi.fn>).mock.calls[0][2]).toBe(
      1,
    );
  });
});

describe('agentVaultProof', () => {
  const MESSAGE = new TextEncoder().encode('atomic-vault-key-derivation-v1');

  function signerReturning(bytes: Uint8Array) {
    return {
      signBytes: async () => btoa(String.fromCharCode(...bytes)),
    };
  }

  it('returns the 64-byte signature', async () => {
    const proof = await agentVaultProof(
      signerReturning(new Uint8Array(64).fill(5)),
      MESSAGE,
    );
    expect(proof).toHaveLength(64);
  });

  /**
   * A signer that handed back a key or a truncated value would produce an
   * envelope nothing could reopen, so the shape is checked at the boundary.
   */
  it('refuses anything that is not a signature', async () => {
    await expect(
      agentVaultProof(signerReturning(new Uint8Array(32).fill(1)), MESSAGE),
    ).rejects.toThrow(/64-byte agent signature/);
  });

  /** Deterministic signatures are what make this usable as key material. */
  it('reproduces the same proof for the same agent', async () => {
    const signer = signerReturning(new Uint8Array(64).fill(9));
    expect(await agentVaultProof(signer, MESSAGE)).toEqual(
      await agentVaultProof(signer, MESSAGE),
    );
  });

  /**
   * WebKit's WebCrypto randomizes Ed25519 nonces, so a live signature there is
   * different every call — and a KEK derived from it never matches the one the
   * envelope was wrapped under. The proof computed from the raw key at sign-in
   * is the one that counts, and the live signer is not consulted at all.
   */
  it('prefers the proof stored at sign-in over a live signature', async () => {
    const stored = new Uint8Array(64).fill(7);
    const signBytes = vi.fn(async () =>
      btoa(String.fromCharCode(...new Uint8Array(64).fill(1))),
    );
    const signer = {
      signBytes,
      vaultProof: btoa(String.fromCharCode(...stored)),
      signsDeterministically: false,
    };

    expect(await agentVaultProof(signer, MESSAGE)).toEqual(stored);
    expect(signBytes).not.toHaveBeenCalled();
  });

  /** The stored proof is only good for the message it was made over. */
  it('ignores the stored proof for a different message', async () => {
    const live = new Uint8Array(64).fill(2);
    const signer = {
      ...signerReturning(live),
      vaultProof: btoa(String.fromCharCode(...new Uint8Array(64).fill(7))),
    };

    expect(
      await agentVaultProof(signer, new TextEncoder().encode('other')),
    ).toEqual(live);
  });

  /**
   * No stored proof and a signer that admits it is non-deterministic: the only
   * way to know whether its signature is usable is to ask twice. A signature
   * that does not reproduce itself must not be turned into a wrapper.
   */
  it('refuses a live signature that does not reproduce itself', async () => {
    let n = 0;
    const signer = {
      signBytes: async () =>
        btoa(String.fromCharCode(...new Uint8Array(64).fill(++n))),
      signsDeterministically: false,
    };

    await expect(agentVaultProof(signer, MESSAGE)).rejects.toThrow(
      /signs differently every time/,
    );
  });

  it('accepts a live signature that does reproduce itself', async () => {
    const signer = {
      ...signerReturning(new Uint8Array(64).fill(3)),
      signsDeterministically: false,
    };

    expect(await agentVaultProof(signer, MESSAGE)).toEqual(
      new Uint8Array(64).fill(3),
    );
  });
});

describe('vaultLaneId', () => {
  /** The control plane validates the shape: 64 lowercase hex characters. */
  it('produces the shape the control plane accepts', async () => {
    const id = await vaultLaneId('device-a');
    expect(id).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is stable for one install and distinct between installs', async () => {
    expect(await vaultLaneId('device-a')).toBe(await vaultLaneId('device-a'));
    expect(await vaultLaneId('device-a')).not.toBe(
      await vaultLaneId('device-b'),
    );
  });
});
