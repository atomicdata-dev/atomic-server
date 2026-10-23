// @vitest-environment jsdom
// @wc-ignore-file
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { useLastEditor } from './useLastEditor';

const getHistoryAttribution = vi.fn();
const localOnly = new Set<string>();
const store = {
  getHistoryAttribution,
  isLocalOnlySubject: (subject: string) => localOnly.has(subject),
};
let resource = { loading: false, hasPendingCommits: false };

let connected = true;
vi.mock('./useServerConnected', () => ({
  useServerConnected: () => connected,
}));
vi.mock('@tomic/react', () => ({
  useStore: () => store,
  useResource: () => resource,
}));

const attribution = (signer: string, createdAt: number) => ({
  signer,
  createdAt,
  destroy: false,
});

describe('useLastEditor', () => {
  beforeEach(() => {
    getHistoryAttribution.mockReset();
    resource = { loading: false, hasPendingCommits: false };
    connected = true;
    localOnly.clear();
  });

  it('returns the newest signer and asks once for the same resource', async () => {
    getHistoryAttribution.mockResolvedValue({
      attributions: [
        attribution('did:ad:agent:old', 1),
        attribution('did:ad:agent:new', 2),
      ],
    });

    const first = renderHook(() => useLastEditor('did:ad:one', 5, true));
    const second = renderHook(() => useLastEditor('did:ad:one', 5, true));

    await waitFor(() => expect(first.result.current).toBe('did:ad:agent:new'));
    await waitFor(() => expect(second.result.current).toBe('did:ad:agent:new'));
    expect(getHistoryAttribution).toHaveBeenCalledTimes(1);
  });

  it('does not ask the server about a resource with edits waiting in the outbox', async () => {
    resource = { loading: false, hasPendingCommits: true };

    const { result } = renderHook(() => useLastEditor('did:ad:two', 5, true));

    await new Promise(resolve => setTimeout(resolve, 20));
    expect(getHistoryAttribution).not.toHaveBeenCalled();
    expect(result.current).toBeUndefined();
  });

  it('does not ask the server about a resource in a local-only drive', async () => {
    localOnly.add('did:ad:local');
    renderHook(() => useLastEditor('did:ad:local', 5, true));

    await new Promise(resolve => setTimeout(resolve, 20));
    expect(getHistoryAttribution).not.toHaveBeenCalled();
  });

  it('does not ask while offline', async () => {
    connected = false;
    renderHook(() => useLastEditor('did:ad:five', 5, true));

    await new Promise(resolve => setTimeout(resolve, 20));
    expect(getHistoryAttribution).not.toHaveBeenCalled();
  });

  it('does not ask while disabled or loading', async () => {
    renderHook(() => useLastEditor('did:ad:three', 5, false));
    resource = { loading: true, hasPendingCommits: false };
    renderHook(() => useLastEditor('did:ad:three', 5, true));

    await new Promise(resolve => setTimeout(resolve, 20));
    expect(getHistoryAttribution).not.toHaveBeenCalled();
  });

  it('does not keep an empty answer, so a later ask tries again', async () => {
    getHistoryAttribution.mockResolvedValueOnce(null);
    renderHook(() => useLastEditor('did:ad:four', 5, true));
    await waitFor(() => expect(getHistoryAttribution).toHaveBeenCalledTimes(1));
    await new Promise(resolve => setTimeout(resolve, 20));

    getHistoryAttribution.mockResolvedValueOnce({
      attributions: [attribution('did:ad:agent:late', 3)],
    });
    const { result } = renderHook(() => useLastEditor('did:ad:four', 5, true));

    await waitFor(() => expect(result.current).toBe('did:ad:agent:late'));
    expect(getHistoryAttribution).toHaveBeenCalledTimes(2);
  });
});
