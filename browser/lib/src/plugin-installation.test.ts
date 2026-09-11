import { expect, it, vi } from 'vitest';
import { requireInstallationServer } from './plugin-installation.js';
import type { Store } from './store.js';

function fixture(local: boolean, error?: Error) {
  const fetchResourceFromServer = vi.fn().mockResolvedValue({ error });
  const store = {
    isLocalOnlyDrive: () => local,
    fetchResourceFromServer,
  } as unknown as Store;

  return { store, fetchResourceFromServer };
}

it('refuses a local workspace without uploading or contacting the server', async () => {
  const { store, fetchResourceFromServer } = fixture(true);
  await expect(requireInstallationServer(store, 'drive')).rejects.toThrow(
    'Sync this workspace',
  );
  expect(fetchResourceFromServer).not.toHaveBeenCalled();
});
it('rejects error resources and network failures before installation', async () => {
  const { store, fetchResourceFromServer } = fixture(
    false,
    new Error('not found'),
  );
  await expect(requireInstallationServer(store, 'drive')).rejects.toThrow(
    'not available',
  );
  fetchResourceFromServer.mockRejectedValue(new Error('network'));
  await expect(requireInstallationServer(store, 'drive')).rejects.toThrow(
    'not available',
  );
});
it('checks server visibility instead of trusting the local cache', async () => {
  const { store, fetchResourceFromServer } = fixture(false);
  await requireInstallationServer(store, 'drive');
  expect(fetchResourceFromServer).toHaveBeenCalledWith('drive', {
    noWebSocket: true,
  });
});
