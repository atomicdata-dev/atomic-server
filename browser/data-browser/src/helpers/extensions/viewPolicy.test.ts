import { expect, it, vi } from 'vitest';
import { core, urls } from '@tomic/react';
import { canViewAccess, type ViewPolicy } from './viewPolicy';

function store(records: Record<string, Record<string, unknown>>) {
  return {
    getResource: vi.fn(async (subject: string) => ({
      subject,
      get: (property: string) => records[subject]?.[property],
      error: records[subject]?.error,
    })),
  };
}

const app: ViewPolicy = { kind: 'app', root: 'root' };
const packaged: ViewPolicy = {
  kind: 'packaged',
  root: 'root',
  classes: ['class'],
  agent: 'plugin-agent',
};

it.each([app, packaged])(
  'shares subtree access without letting a sibling become a root: $kind',
  async policy => {
    const db = store({
      child: { [core.properties.parent]: 'root' },
      sibling: { [core.properties.parent]: 'drive' },
    });
    expect(await canViewAccess(db as never, 'child', policy, 'write')).toBe(
      true,
    );
    expect(await canViewAccess(db as never, 'sibling', policy, 'write')).toBe(
      false,
    );
  },
);

it('keeps packaged class/public/agent read grants separate from app write authority', async () => {
  const db = store({
    property: { [core.properties.parent]: 'class' },
    public: { [core.properties.read]: [urls.instances.publicAgent] },
    granted: { [core.properties.write]: ['plugin-agent'] },
  });
  for (const subject of ['property', 'public', 'granted'])
    expect(await canViewAccess(db as never, subject, packaged, 'read')).toBe(
      true,
    );
  expect(await canViewAccess(db as never, 'public', packaged, 'write')).toBe(
    false,
  );
  expect(await canViewAccess(db as never, 'granted', packaged, 'write')).toBe(
    true,
  );
  expect(await canViewAccess(db as never, 'granted', app, 'write')).toBe(false);
});

it.each([app, packaged])(
  'fails closed on cycles, missing parents and unavailable ancestry: $kind',
  async policy => {
    const db = store({
      a: { [core.properties.parent]: 'b' },
      b: { [core.properties.parent]: 'a' },
      broken: { error: new Error('Forbidden') },
    });
    expect(await canViewAccess(db as never, 'a', policy, 'write')).toBe(false);
    expect(db.getResource).toHaveBeenCalledTimes(2);
    expect(await canViewAccess(db as never, 'missing', policy, 'write')).toBe(
      false,
    );
    await expect(
      canViewAccess(db as never, 'broken', policy, 'write'),
    ).rejects.toThrow('Forbidden');
  },
);

it('preserves deep inherited packaged grants without extending app write depth', async () => {
  const records: Record<string, Record<string, unknown>> = {};
  for (let i = 0; i < 20; i++)
    records[String(i)] = { [core.properties.parent]: String(i + 1) };
  records['20'] = { [core.properties.write]: ['plugin-agent'] };
  const db = store(records);
  expect(await canViewAccess(db as never, '0', packaged, 'write')).toBe(true);
  expect(
    await canViewAccess(
      db as never,
      '0',
      { ...packaged, agent: undefined },
      'write',
    ),
  ).toBe(false);
  expect(await canViewAccess(db as never, '0', app, 'write')).toBe(false);
});
