import { describe, expect, it, vi } from 'vitest';
import { unlockMethods } from './sendIdentity';
import type { RecoverySecret } from './recovery';

const managedFetch = vi.fn();

vi.mock('./api', () => ({
  managedFetch: (...a: unknown[]) => managedFetch(...a),
}));

const KEY = 'B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw';

function backup(
  kinds: Array<'webauthn-prf' | 'recovery-code' | 'atomic-assisted'>,
  format_version = 2,
): RecoverySecret {
  return {
    owner_email: 'a@example.com',
    agent_subject: 'did:ad:agent:x',
    encrypted_secret: '',
    encryption_algorithm: 'AES-GCM',
    kdf_algorithm: '',
    kdf_params: {},
    salt: '',
    nonce: '',
    format_version,
    wrappers: kinds.map(wrapper_type => ({
      wrapper_type,
      kdf_algorithm: '',
      kdf_params: {},
      salt: '',
      wrapped_dek: '',
      wrap_nonce: '',
      created_at: 0,
    })),
    created_at: 0,
    updated_at: 0,
  };
}

describe('unlockMethods', () => {
  it('prefers the account when it owns the backup', () => {
    const b = backup(['webauthn-prf', 'atomic-assisted']);

    expect(unlockMethods(b, 'a@example.com')).toEqual(['assisted', 'passkey']);
  });

  it('does not use the assisted wrapper for another account', () => {
    const b = backup(['recovery-code', 'atomic-assisted']);

    expect(unlockMethods(b, 'other@example.com')).toEqual(['code']);
    expect(unlockMethods(b, undefined)).toEqual(['code']);
  });

  it('lists passkey before code, and v1 only knows its password', () => {
    expect(
      unlockMethods(backup(['recovery-code', 'webauthn-prf']), 'x'),
    ).toEqual(['passkey', 'code']);
    expect(unlockMethods(backup([], 1), 'a@example.com')).toEqual(['password']);
  });
});

describe('describeLink and depositSealedIdentity', () => {
  it('reads the app key and device name, ignoring a malformed key', async () => {
    const { describeLink } = await import('./sendIdentity');

    managedFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          device_name: 'Pixel',
          already_approved: false,
          app_key: KEY,
        }),
      ),
    );
    expect(await describeLink('ABCD-1234')).toEqual({
      deviceName: 'Pixel',
      alreadyApproved: false,
      appKey: KEY,
    });

    managedFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ device_name: 'Pixel', app_key: 'short' })),
    );
    expect((await describeLink('ABCD-1234')).appKey).toBeNull();
  });

  it('posts the sealed blob and reports a second deposit', async () => {
    const { depositSealedIdentity } = await import('./sendIdentity');
    const sealed = { epk: 'e', nonce: 'n', ciphertext: 'c' };

    managedFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    await depositSealedIdentity('ABCD-1234', sealed);
    expect(managedFetch).toHaveBeenLastCalledWith(
      '/device-link/code/ABCD-1234/identity',
      expect.objectContaining({ method: 'POST', body: JSON.stringify(sealed) }),
    );

    managedFetch.mockResolvedValueOnce(new Response('{}', { status: 409 }));
    await expect(depositSealedIdentity('ABCD-1234', sealed)).rejects.toThrow(
      /already used/,
    );
  });
});
