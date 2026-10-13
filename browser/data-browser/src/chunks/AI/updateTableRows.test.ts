import { expect, it, vi } from 'vitest';
import { core, type Store } from '@tomic/lib';
import { updateTableRows } from './updateTableRows';
vi.mock('@tomic/react', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/react')>()),
  buildClassContext: async () => ({}),
  resolveKey: (_: unknown, key: string) => ({ subject: key }),
  coerceValueIn: (_: unknown, value: unknown) => value,
}));

function fixture() {
  const row = (parent: string) => ({
    subject: parent === 'table' ? 'row1' : 'row2',
    get: (p: string) => (p === core.properties.parent ? parent : undefined),
    canWrite: async () => true,
    getClasses: () => [],
    clone: () => ({}),
    set: vi.fn(),
    save: vi.fn(),
  });
  const first = row('table');
  const second = { ...row('table'), subject: 'row2' };
  const resources = {
    table: { hasClasses: () => true },
    row1: first,
    row2: second,
  };
  const store = {
    getAgent: () => ({ subject: 'user' }),
    getResource: async (s: keyof typeof resources) => resources[s],
  } as unknown as Store;

  return { store, first, second };
}

it('saves multiple row patches in one invocation', async () => {
  const { store, first, second } = fixture();
  expect(
    await updateTableRows(store, 'table', [
      { subject: 'row1', values: { photo: 'image1' } },
      { subject: 'row2', values: { photo: 'image2' } },
    ]),
  ).toEqual({ updated: ['row1', 'row2'] });
  expect(first.set).toHaveBeenCalledWith('photo', 'image1');
  expect(second.save).toHaveBeenCalledOnce();
});
it('rejects an out-of-table row before writing any rows', async () => {
  const { store, first, second } = fixture();
  second.get = () => 'other';
  const result = await updateTableRows(store, 'table', [
    { subject: 'row1', values: { photo: 'image1' } },
    { subject: 'row2', values: { photo: 'image2' } },
  ]);
  expect(result).toMatchObject({
    updated: [],
    error: expect.stringContaining('does not belong'),
  });
  expect(first.set).not.toHaveBeenCalled();
});
it('reports completed rows when a later save fails', async () => {
  const { store, second } = fixture();
  second.save.mockRejectedValue(new Error('offline'));
  const result = await updateTableRows(store, 'table', [
    { subject: 'row1', values: { photo: 'image1' } },
    { subject: 'row2', values: { photo: 'image2' } },
  ]);
  expect(result).toMatchObject({
    updated: ['row1'],
    error: expect.stringContaining('offline'),
  });
});
it('checks every row permission before starting writes', async () => {
  const { store, first, second } = fixture();
  second.canWrite = async () => false;
  const result = await updateTableRows(store, 'table', [
    { subject: 'row1', values: { photo: 'image1' } },
    { subject: 'row2', values: { photo: 'image2' } },
  ]);
  expect(result).toMatchObject({
    updated: [],
    error: expect.stringContaining('cannot edit'),
  });
  expect(first.set).not.toHaveBeenCalled();
});
