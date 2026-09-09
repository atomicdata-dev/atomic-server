// @wc-ignore-file
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { managedFetch } from './api';
import { getManagedAccount } from './session';
import {
  addPasskeyWrapper,
  buildEnvelopeWithPasskeyAndCode,
  decryptEnvelopeV2,
  decryptEnvelopeWithPasskey,
  revealSecretFromBackup,
  type RecoverySecret,
} from './recovery';

vi.mock('./session', () => ({ getManagedAccount: vi.fn() }));
vi.mock('./api', () => ({ managedFetch: vi.fn() }));
vi.mock('../wasmUrls', () => ({
  wasmJsUrl: () => './test-fixtures/recovery-wasm.ts',
  wasmBinaryUrl: () => '',
}));
vi.mock('./binding', () => ({ writeManagedAccountBinding: vi.fn() }));

let stored: RecoverySecret;
let code: string;
let credentialNumber: number;
let selectedCredential: number;
const create = vi.fn();
const get = vi.fn();
const subject = 'did:ad:agent:test-account';

function credential(n: number) {
  return {
    rawId: new Uint8Array([n]).buffer,
    response: {},
    getClientExtensionResults: () => ({
      prf: {
        enabled: true,
        results: { first: new Uint8Array(32).fill(n).buffer },
      },
    }),
  };
}

beforeEach(async () => {
  vi.clearAllMocks();
  vi.stubGlobal('crypto', webcrypto);
  vi.stubGlobal('navigator', { credentials: { create, get } });
  credentialNumber = 0;
  selectedCredential = 1;
  create.mockImplementation(async () => credential(++credentialNumber));
  get.mockImplementation(async () => credential(selectedCredential));
  vi.mocked(getManagedAccount).mockResolvedValue({
    email: 'test@example.com',
  } as never);
  const built = await buildEnvelopeWithPasskeyAndCode({
    secret: 'test-agent-secret',
    agentSubject: subject,
    userName: 'Test',
  });
  code = built.recoveryCode;
  stored = {
    ...built.request,
    owner_email: 'test@example.com',
    wrappers: built.request.wrappers!.map(w => ({ ...w, created_at: 1 })),
  } as RecoverySecret;
  vi.mocked(managedFetch).mockImplementation(async (_path, options) => {
    if (options?.method === 'PUT') {
      const input = JSON.parse(options.body as string);
      stored = {
        ...stored,
        ...input,
        wrappers: input.wrappers.map((w: object) => ({ ...w, created_at: 2 })),
      };
    }

    return new Response(JSON.stringify(stored), { status: 200 });
  });
}, 60000);
afterEach(() => vi.unstubAllGlobals());

describe('recovery-code passkey enrollment', () => {
  it('reveals with a supplied code without requiring WebAuthn', async () => {
    get.mockRejectedValue(new Error('Web Authentication unavailable'));
    expect(await revealSecretFromBackup(code, subject)).toBe(
      'test-agent-secret',
    );
    expect(get).not.toHaveBeenCalled();
  }, 60000);

  it('preserves the code and old passkey, and can unlock using the new passkey', async () => {
    const original = structuredClone(stored);
    const saved = await addPasskeyWrapper(code, subject, 'Test');
    expect(saved.encrypted_secret).toBe(original.encrypted_secret);
    expect(saved.nonce).toBe(original.nonce);
    expect(
      saved.wrappers.map(({ created_at: _, ...w }) => w).slice(0, 2),
    ).toEqual(original.wrappers.map(({ created_at: _, ...w }) => w));
    expect(await decryptEnvelopeV2(saved, code)).toBe('test-agent-secret');
    expect(await decryptEnvelopeWithPasskey(saved)).toBe('test-agent-secret');
    selectedCredential = 2;
    expect(await decryptEnvelopeWithPasskey(saved)).toBe('test-agent-secret');
    const options = get.mock.calls.at(-1)![0];
    expect(options.publicKey.allowCredentials).toHaveLength(2);
    expect(
      Object.keys(options.publicKey.extensions.prf.evalByCredential),
    ).toEqual(['AQ', 'Ag']);
  }, 60000);

  it('does not create a credential or write when the recovery code is wrong', async () => {
    create.mockClear();
    await expect(
      addPasskeyWrapper('wrong-code', subject, 'Test'),
    ).rejects.toThrow('Wrong recovery code');
    expect(create).not.toHaveBeenCalled();
    expect(
      vi
        .mocked(managedFetch)
        .mock.calls.some(([, options]) => options?.method === 'PUT'),
    ).toBe(false);
  }, 60000);

  it('does not enroll a passkey for a different signed-in account', async () => {
    create.mockClear();
    await expect(
      addPasskeyWrapper(code, 'did:ad:agent:other', 'Test'),
    ).rejects.toThrow('Sign in to the account');
    expect(create).not.toHaveBeenCalled();
  });
  it('keeps the existing backup when passkey creation is cancelled', async () => {
    const original = structuredClone(stored);
    create.mockRejectedValue(new DOMException('Cancelled', 'NotAllowedError'));
    await expect(addPasskeyWrapper(code, subject, 'Test')).rejects.toThrow(
      'Cancelled',
    );
    expect(stored).toEqual(original);
    expect(
      vi
        .mocked(managedFetch)
        .mock.calls.some(([, options]) => options?.method === 'PUT'),
    ).toBe(false);
  }, 60000);
});
