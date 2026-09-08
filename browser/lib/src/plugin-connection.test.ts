import { describe, expect, it, vi } from 'vitest';
import {
  approveExternalIntent,
  readConnectionSubjects,
  checkpointConnection,
  confirmExternalOperation,
  inspectExternalOperation,
} from './plugin-connection.js';
vi.mock('./authentication.js', () => ({
  signRequest: async () => ({ authorization: 'signed' }),
}));

describe('external approval transport', () => {
  const approval = {
    drive: 'drive',
    plugin: 'plugin',
    release: 'blake3:release',
    run: 'run-1',
    intent: {
      id: 'one',
      operation: 'create',
      method: 'POST',
      url: 'https://provider.test/items',
    },
  };
  it('does not automatically repeat a request after a lost response', async () => {
    const transport = vi.fn().mockRejectedValue(new Error('lost response'));
    const store = {
      getAgent: () => ({}) as never,
      getServerUrl: () => 'https://atomic.test',
    };
    await expect(
      approveExternalIntent(store, approval, transport),
    ).rejects.toThrow('lost response');
    expect(transport).toHaveBeenCalledTimes(1);
    expect(JSON.parse(transport.mock.calls[0][1].body)).toEqual(approval);
  });
  it('requires an account before making any request', async () => {
    const transport = vi.fn();
    const store = {
      getAgent: () => undefined,
      getServerUrl: () => 'https://atomic.test',
    };
    await expect(
      approveExternalIntent(store, approval, transport),
    ).rejects.toThrow('sign in');
    expect(transport).not.toHaveBeenCalled();
  });
});

describe('connection recovery transport', () => {
  const store = {
    getAgent: () => ({}) as never,
    getServerUrl: () => 'https://atomic.test',
  };
  const operation = {
    drive: 'd',
    plugin: 'p',
    release: 'v',
    run: 'r',
    intent: 'i',
  };
  it('inspects a missing receipt without resending an effect', async () => {
    const transport = vi.fn().mockResolvedValue(new Response('null'));
    expect(
      await inspectExternalOperation(store, operation, transport),
    ).toBeNull();
    expect(transport.mock.calls[0][0]).toBe(
      'https://atomic.test/plugin-external-status',
    );
    expect(JSON.parse(transport.mock.calls[0][1].body)).toEqual(operation);
  });
  it('sends evidence but lets the server establish the audit actor', async () => {
    const transport = vi
      .fn()
      .mockResolvedValue(new Response('{"resolved":true}'));
    const receipt = { status: 201, body: 'provider-record-1' };
    await confirmExternalOperation(
      store,
      operation,
      receipt,
      'Provider audit 123',
      transport,
    );
    expect(JSON.parse(transport.mock.calls[0][1].body)).toEqual({
      operation,
      receipt,
      evidence: 'Provider audit 123',
    });
  });
  it('does not retry a stale checkpoint or hide the conflict', async () => {
    const transport = vi
      .fn()
      .mockResolvedValue(
        new Response('connection state changed', { status: 400 }),
      );
    await expect(
      checkpointConnection(
        store,
        { drive: 'd', plugin: 'p' },
        { revision: 7, records: [], cursor: null },
        transport,
      ),
    ).rejects.toThrow('connection state changed');
    expect(transport).toHaveBeenCalledTimes(1);
  });
});

describe('strict connection queries', () => {
  it('refuses a failed query instead of treating it as empty', async () => {
    const store = {
      getServerUrl: () => 'https://atomic.test',
      fetchResourceFromServer: vi
        .fn()
        .mockResolvedValue({ error: new Error('offline') }),
    };
    await expect(
      readConnectionSubjects(store, 'drive', 'property', 'value'),
    ).rejects.toThrow('refusing');
  });
  it('refuses incomplete pages before an adapter can create duplicates', async () => {
    const store = {
      getServerUrl: () => 'https://atomic.test',
      fetchResourceFromServer: vi.fn().mockResolvedValue({
        error: undefined,
        getLoroDoc: () => undefined,
        get: (property: string) => (property.endsWith('totalMembers') ? 3 : []),
      }),
    };
    await expect(
      readConnectionSubjects(store, 'drive', 'property', 'value'),
    ).rejects.toThrow('Incomplete');
  });
});
