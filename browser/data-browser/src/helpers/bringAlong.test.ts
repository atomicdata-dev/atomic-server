// @wc-ignore-file
import { beforeEach, describe, expect, it, vi } from 'vitest';

const m = vi.hoisted(() => ({
  archive: vi.fn(),
  workspace: vi.fn(),
  list: vi.fn(),
  handOver: vi.fn(),
  applyPending: vi.fn(),
  capture: vi.fn(),
  agent: undefined as { subject: string; privateDrive?: string } | undefined,
}));

vi.mock('./agentStorage', () => ({ archiveStoredAgent: m.archive }));
vi.mock('./clientDbMode', () => ({ isClientDbEnabled: () => false }));
vi.mock('./managed', () => ({
  localAgentWorkspace: m.workspace,
  sameAgent: (a: string, b: string) =>
    a.replace(/^did:ad:/, 'atomic:') === b.replace(/^did:ad:/, 'atomic:'),
}));
vi.mock('./managed/driveCarryOver', () => ({
  importDriveCarryOver: vi.fn(),
  stageDriveCarryOver: vi.fn(),
}));
vi.mock('./managed/driveHandover', () => ({
  applyPendingDriveHandover: m.applyPending,
  handOverDrives: m.handOver,
  listHandoverDrives: m.list,
}));
vi.mock('../chunks/Templates/demoSession', () => ({
  readInteractiveDemo: () => ({ drive: 'did:ad:demo' }),
  readTemplateDemo: () => undefined,
}));
vi.mock('@sentry/react', () => ({ captureException: m.capture }));

import { hasWorkToBring, prepareIdentitySwitch } from './bringAlong';

const store = { getAgent: () => m.agent } as never;
const A = 'did:ad:agent:a';
const B = 'did:ad:agent:b';

beforeEach(() => {
  vi.clearAllMocks();
  m.agent = { subject: A, privateDrive: 'did:ad:homeA' };
  m.archive.mockResolvedValue(undefined);
  m.workspace.mockResolvedValue('some');
  m.list.mockResolvedValue(['did:ad:notes']);
  m.handOver.mockResolvedValue({ agent: B, drives: [] });
});

describe('prepareIdentitySwitch', () => {
  it('is a plain sign-in when the browser holds no one', async () => {
    m.agent = undefined;
    const ask = vi.fn();

    expect(await prepareIdentitySwitch(store, B, ask)).toBe('plain');
    expect(m.archive).not.toHaveBeenCalled();
    expect(ask).not.toHaveBeenCalled();
  });

  it('is a plain sign-in as the same one (other spelling)', async () => {
    const ask = vi.fn();

    expect(await prepareIdentitySwitch(store, 'atomic:agent:a', ask)).toBe(
      'plain',
    );
    expect(m.archive).not.toHaveBeenCalled();
  });

  it('archives without asking when A has no work', async () => {
    m.workspace.mockResolvedValue('none');
    const ask = vi.fn();

    expect(await prepareIdentitySwitch(store, B, ask)).toBe('left');
    expect(m.archive).toHaveBeenCalledWith(A);
    expect(ask).not.toHaveBeenCalled();
    expect(m.handOver).not.toHaveBeenCalled();
  });

  it('does not ask for an empty home (only the demo is listed)', async () => {
    m.list.mockResolvedValue(['did:ad:demo']);
    const ask = vi.fn();

    expect(await prepareIdentitySwitch(store, B, ask)).toBe('left');
    expect(ask).not.toHaveBeenCalled();
  });

  it('asks when A has work, and brings it along on yes', async () => {
    const ask = vi.fn().mockResolvedValue(true);

    expect(await prepareIdentitySwitch(store, B, ask)).toBe('brought');
    expect(m.archive).toHaveBeenCalledWith(A);
    expect(ask).toHaveBeenCalledOnce();
    expect(m.handOver).toHaveBeenCalledWith(
      store,
      expect.objectContaining({ from: A, to: B }),
    );
  });

  it('only archives on leave', async () => {
    const ask = vi.fn().mockResolvedValue(false);

    expect(await prepareIdentitySwitch(store, B, ask)).toBe('left');
    expect(m.archive).toHaveBeenCalledWith(A);
    expect(m.handOver).not.toHaveBeenCalled();
  });

  it('archives before it asks', async () => {
    const order: string[] = [];
    m.archive.mockImplementation(async () => void order.push('archive'));

    await prepareIdentitySwitch(store, B, async () => {
      order.push('ask');

      return false;
    });
    expect(order).toEqual(['archive', 'ask']);
  });

  it('throws when bringing along fails, so the sign-in stops', async () => {
    m.handOver.mockRejectedValue(new Error('boom'));

    await expect(
      prepareIdentitySwitch(store, B, async () => true),
    ).rejects.toThrow('boom');
  });

  it('still asks when archiving fails (reported)', async () => {
    m.archive.mockRejectedValue(new Error('no stored key'));
    const ask = vi.fn().mockResolvedValue(false);

    expect(await prepareIdentitySwitch(store, B, ask)).toBe('left');
    expect(m.capture).toHaveBeenCalled();
    expect(ask).toHaveBeenCalled();
  });
});

describe('hasWorkToBring', () => {
  it('counts an unreadable workspace as work', async () => {
    m.workspace.mockResolvedValue('unknown');

    expect(await hasWorkToBring(store, A)).toBe(true);
  });

  it('counts an unreadable drive list as work', async () => {
    m.list.mockRejectedValue(new Error('offline'));

    expect(await hasWorkToBring(store, A)).toBe(true);
  });
});
