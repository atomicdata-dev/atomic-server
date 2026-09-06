import { describe, it, expect, vi, beforeEach } from 'vitest';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...a: unknown[]) => invoke(...a),
}));

const { nodeVault } = await import('./nodeVault');

beforeEach(() => {
  invoke.mockReset();
});

/**
 * These tests are about the boundary, not the vault.
 *
 * Sealed bytes and drive keys are the two things crossing IPC, and getting
 * exactly that wrong once already stored a stringified byte array in every
 * vault object — uploaded, confirmed, and unreadable. So assert the bytes
 * survive the trip rather than that the call was made.
 */
describe('nodeVault', () => {
  const key = new Uint8Array(32).fill(7);

  it('sends the key as base64 and brings sealed bytes back intact', async () => {
    const sealed = new Uint8Array([0, 1, 254, 255, 127, 128]);
    invoke.mockResolvedValue({
      objectKey: 'v1/drive/lane/000001',
      sealed: btoa(String.fromCharCode(...sealed)),
      kind: 'pack',
      resources: 3,
      unchanged: 9,
      tombstones: 1,
      coverage: {},
    });

    const result = await nodeVault.vaultExport(
      'did:ad:drive',
      key,
      2,
      'pseudo',
      'dev',
      1,
      1,
      true,
      {},
    );

    const [command, args] = invoke.mock.calls[0] as [
      string,
      Record<string, unknown>,
    ];
    expect(command).toBe('vault_export');
    expect(typeof args.key).toBe('string');
    expect(args.keyEpoch).toBe(2);

    expect(result?.sealed).toBeInstanceOf(Uint8Array);
    expect([...(result?.sealed ?? [])]).toEqual([...sealed]);
    expect(result?.objectKey).toBe('v1/drive/lane/000001');
    expect(result?.resources).toBe(3);
    expect(result?.kind).toBe('pack');
    expect(result?.unchanged).toBe(
      9,
      // The count the whole incremental pass exists to make large.
    );
  });

  /**
   * Nothing to back up is an answer, not a failure — and since incremental
   * cursors landed it is the ordinary answer for an idle device.
   */
  it('passes through the "nothing changed since the cursor" null', async () => {
    invoke.mockResolvedValue(null);
    expect(
      await nodeVault.vaultExport(
        'did:ad:drive',
        key,
        1,
        'p',
        'd',
        4,
        1,
        true,
        {},
      ),
    ).toBeNull();
  });

  /**
   * A checkpoint crosses the boundary as a different `kind` and carries the
   * coverage map the caller must publish. Losing either would leave the control
   * plane storing an anchor it does not know it can prune against.
   */
  it('carries a checkpoint kind and its coverage across the IPC boundary', async () => {
    invoke.mockResolvedValue({
      objectKey: 'vault/pseudo/checkpoints/ckpt-000002.loro',
      sealed: btoa('xx'),
      kind: 'checkpoint',
      resources: 40,
      unchanged: 0,
      tombstones: 2,
      coverage: { dev: 7 },
    });

    const result = await nodeVault.vaultExport(
      'did:ad:drive',
      key,
      1,
      'pseudo',
      'dev',
      8,
      2,
      true,
      { dev: 7 },
    );

    expect(result?.kind).toBe('checkpoint');
    expect(result?.coverage).toEqual({ dev: 7 });

    const [, args] = invoke.mock.calls[0] as [string, Record<string, unknown>];
    expect(args.checkpointN).toBe(2);
    expect(args.observedLanes).toEqual({ dev: 7 });
  });

  it('encodes objects for import and passes them through in listing order', async () => {
    invoke.mockResolvedValue({
      packsRead: 2,
      resourcesRestored: 5,
      tombstonesApplied: 0,
      objectsSkipped: 1,
      objectsUnreadable: 0,
    });

    const objects = [
      { objectKey: 'a/000001', sealed: new Uint8Array([1, 2]) },
      { objectKey: 'a/000002', sealed: new Uint8Array([3, 4]) },
    ];
    const outcome = await nodeVault.vaultImport(
      key,
      1,
      'pseudo',
      'dev',
      objects,
    );

    const [, args] = invoke.mock.calls[0] as [string, Record<string, unknown>];
    const sent = args.objects as { objectKey: string; sealed: string }[];

    // The list crosses intact; the *application* order is decided on the other
    // side by `plan_restore`, from the newest checkpoint's coverage and
    // observed maps. What must not happen here is objects being dropped or
    // reordered on the way.
    expect(sent.map(o => o.objectKey)).toEqual(['a/000001', 'a/000002']);
    expect(sent.every(o => typeof o.sealed === 'string')).toBe(true);
    expect(outcome.resourcesRestored).toBe(5);
  });

  it('commits a segment by name', async () => {
    invoke.mockResolvedValue(undefined);
    await nodeVault.vaultCommitSegment('pseudo', 'dev', 9);

    expect(invoke).toHaveBeenCalledWith('vault_commit_segment', {
      drivePseudonym: 'pseudo',
      devicePubkey: 'dev',
      segment: 9,
    });
  });
});
