// @wc-ignore-file
import { expect, it, vi } from 'vitest';
import {
  requireStorageAccount,
  summarizeVaultContents,
  type PackInspection,
} from './vaultContents';
import type { VaultObject } from './vault';
import { getManagedAccount } from './session';
vi.mock('./session', () => ({ getManagedAccount: vi.fn() }));
const object = (id: string, kind: string, size: number): VaultObject => ({
  object_id: id,
  object_key: id,
  kind,
  size_bytes: size,
  key_epoch: 1,
  lane_device_pubkey: null,
  segment: null,
});
const pack: PackInspection = {
  entries: [
    {
      subject: 'atomic:note',
      name: 'Project notes',
      updateBytes: 100,
      envelopeBytes: 200,
      blobHashes: ['hash'],
    },
  ],
  structureBytes: 50,
  blobs: [{ hash: 'hash', content_id: 'content', size: 1000, chunks: 1 }],
};
it('counts retained copies, file bytes and unknown objects once and reconciles the inventory', () => {
  const result = summarizeVaultContents(
    [
      object('a', 'checkpoint', 350),
      object('b', 'pack', 350),
      object('vault/drive/blobs/content/000000', 'blob', 1046),
      object('bad', 'pack', 80),
      object('index', 'index', 20),
    ],
    new Map<string, PackInspection | string>([
      ['a', pack],
      ['b', pack],
      ['bad', 'Wrong key'],
    ]),
  );
  expect(result.storedBytes).toBe(1846);
  expect(result.items.reduce((sum, item) => sum + item.bytes, 0)).toBe(
    result.storedBytes,
  );
  expect(result.items.find(item => item.kind === 'resource')).toMatchObject({
    bytes: 600,
    updateBytes: 200,
    envelopeBytes: 400,
    copies: 2,
    name: 'Project notes',
  });
  expect(result.items.find(item => item.kind === 'file')).toMatchObject({
    bytes: 1046,
    subjects: ['atomic:note'],
    name: 'Project notes (file bytes)',
  });
  expect(result.unreadable).toBe(1);
  expect(result.items.find(item => item.kind === 'unreadable')).toMatchObject({
    bytes: 80,
    error: 'Wrong key',
  });
});
it('counts a shared attachment once and keeps all referring resources', () => {
  const shared = {
    ...pack,
    entries: [
      ...pack.entries,
      { ...pack.entries[0], subject: 'atomic:second', name: 'Second file' },
    ],
  };
  const result = summarizeVaultContents(
    [
      object('a', 'checkpoint', 650),
      object('vault/drive/blobs/content/000000', 'blob', 1046),
    ],
    new Map([['a', shared]]),
  );
  expect(result.items.filter(item => item.kind === 'file')).toEqual([
    expect.objectContaining({
      bytes: 1046,
      subjects: ['atomic:note', 'atomic:second'],
    }),
  ]);
});
it('refuses a fabricated attribution rather than scaling it to fit', () => {
  expect(() =>
    summarizeVaultContents(
      [object('a', 'checkpoint', 999)],
      new Map([['a', pack]]),
    ),
  ).toThrow('do not match');
});
it('does not claim unknown blob bytes belong to a live or deleted resource', () => {
  const result = summarizeVaultContents(
    [object('vault/drive/blobs/other/000000', 'blob', 123)],
    new Map(),
  );
  expect(result.items[0]).toMatchObject({
    bytes: 123,
    subjects: [],
    name: 'Unattributed file bytes',
  });
});
it('requires the same account and an active scan before proceeding', async () => {
  vi.mocked(getManagedAccount).mockResolvedValue({
    email: 'different',
    address: 'display@example.com',
  });
  await expect(requireStorageAccount('owner')).rejects.toThrow(
    'Account changed',
  );
  vi.mocked(getManagedAccount).mockResolvedValue({ email: 'owner' });
  const controller = new AbortController();
  controller.abort();
  await expect(
    requireStorageAccount('owner', controller.signal),
  ).rejects.toThrow();
  await expect(requireStorageAccount('owner')).resolves.toBeUndefined();
});
