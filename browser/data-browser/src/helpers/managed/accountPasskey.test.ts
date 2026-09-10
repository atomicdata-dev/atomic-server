// @wc-ignore-file
import { beforeEach, expect, it, vi } from 'vitest';
import { accountPasskey } from './accountPasskey';
import { hasManagedApi, managedFetch } from './api';
import { getManagedAccount } from './session';
vi.mock('./api', () => ({ hasManagedApi: vi.fn(), managedFetch: vi.fn() }));
vi.mock('./session', () => ({ getManagedAccount: vi.fn() }));
const create = vi.fn();
const get = vi.fn();
const salt = new Uint8Array(16).fill(9);
const prf = new Uint8Array(32).fill(123).buffer;
const credential = {
  rawId: new Uint8Array([1]).buffer,
  response: {
    clientDataJSON: new Uint8Array([2]).buffer,
    authenticatorData: new Uint8Array([3]).buffer,
    signature: new Uint8Array([4]).buffer,
    userHandle: new Uint8Array([5]).buffer,
    attestationObject: new Uint8Array([6]).buffer,
  },
  getClientExtensionResults: () => ({ prf: { results: { first: prf } } }),
};
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubGlobal('navigator', { credentials: { create, get } });
  vi.mocked(hasManagedApi).mockReturnValue(true);
  vi.mocked(getManagedAccount).mockResolvedValue({
    email: 'owner@example.com',
  });
  create.mockResolvedValue(credential);
  get.mockResolvedValue(credential);
});

function api(existing: boolean, finishStatus = 204) {
  vi.mocked(managedFetch).mockImplementation(async path => {
    if (path === '/passkeys')
      return Response.json({ credential_ids: existing ? ['AQ'] : [] });
    if (path.endsWith('/start'))
      return Response.json({
        publicKey: {
          challenge: 'Ag',
          rpId: 'localhost',
          allowCredentials: [{ type: 'public-key', id: 'AQ' }],
          rp: { id: 'localhost', name: 'Atomic account' },
          user: { id: 'BQ', name: 'owner@example.com', displayName: 'Owner' },
        },
      });

    return new Response(null, { status: finishStatus });
  });
}

it('reuses a login credential and never transmits PRF results', async () => {
  api(true);
  expect(await accountPasskey(salt)).toMatchObject({
    credential,
    rpId: 'localhost',
    existing: true,
  });
  expect(create).not.toHaveBeenCalled();
  expect(get.mock.calls[0][0].publicKey.extensions.prf.eval.first).toEqual(
    salt,
  );
  const body = JSON.parse(
    vi.mocked(managedFetch).mock.calls.at(-1)![1]!.body as string,
  );
  expect(body.clientExtensionResults).toEqual({});
  expect(body.response).toEqual({
    clientDataJSON: 'Ag',
    authenticatorData: 'Aw',
    signature: 'BA',
    userHandle: 'BQ',
  });
});
it('registers one discoverable credential with the server challenge and only attestation data', async () => {
  api(false);
  await accountPasskey(salt);
  expect(get).not.toHaveBeenCalled();
  expect(create.mock.calls[0][0].publicKey.challenge).toEqual(
    new Uint8Array([2]),
  );
  expect(
    create.mock.calls[0][0].publicKey.authenticatorSelection.residentKey,
  ).toBe('required');
  const body = JSON.parse(
    vi.mocked(managedFetch).mock.calls.at(-1)![1]!.body as string,
  );
  expect(body.clientExtensionResults).toEqual({});
  expect(body.response.attestationObject).toBe('Bg');
});
it('does not accept an unverified account credential', async () => {
  api(true, 401);
  await expect(accountPasskey(salt)).rejects.toThrow('Could not set up');
});
it('does not create a second credential on cancellation', async () => {
  api(true);
  get.mockResolvedValue(null);
  await expect(accountPasskey(salt)).rejects.toThrow('cancelled');
  expect(create).not.toHaveBeenCalled();
});
it('keeps standalone recovery independent of the portal', async () => {
  vi.mocked(hasManagedApi).mockReturnValue(false);
  expect(await accountPasskey(salt)).toBeNull();
  expect(managedFetch).not.toHaveBeenCalled();
});
