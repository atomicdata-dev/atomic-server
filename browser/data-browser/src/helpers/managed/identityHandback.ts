/**
 * Sealing an identity for an app that asked the browser to hand it over
 * (planning/flutter-secret-handback.md).
 *
 * The app made an X25519 key pair that lives in its memory only and gave the
 * public half to the provider. We seal the secret to it so the provider, which
 * relays the blob, learns nothing. Scheme: ephemeral sender X25519 key, ECDH
 * with the app key, HKDF-SHA256 (empty salt, info = label || app_key || epk),
 * AES-256-GCM with a random 12-byte nonce. The Dart twin lives in
 * `packages/atomic_flutter/lib/src/account/identity_handback.dart`; both are
 * tested against `packages/atomic_flutter/test/fixtures/identity_handback_vector.json`.
 */

const INFO_LABEL = 'atomic-identity-handback-v1';

/** PKCS#8 prefix of a raw 32-byte X25519 private key, so a fixed seed can be imported. */
const X25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04,
  0x22, 0x04, 0x20,
]);

export type SealedIdentity = { epk: string; nonce: string; ciphertext: string };

export type HandbackPayload = {
  secret: string;
  subject: string;
  drive: string | null;
};

/** For tests: pin the randomness so the output can be compared to a vector. */
export type SealOverrides = { senderSeed?: Uint8Array; nonce?: Uint8Array };

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';

  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function fromBase64Url(input: string): Uint8Array<ArrayBuffer> {
  const standard = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

  return bytes;
}

/** Is this a usable `app_key`: base64url of exactly 32 bytes? */
export function isValidAppKey(appKey: unknown): appKey is string {
  if (typeof appKey !== 'string' || !/^[A-Za-z0-9_-]{43}=*$/.test(appKey)) {
    return false;
  }

  try {
    return fromBase64Url(appKey).length === 32;
  } catch {
    return false;
  }
}

/** Seal `payload` to the app's public key. */
export async function sealIdentity(
  appKey: string,
  payload: HandbackPayload,
  overrides: SealOverrides = {},
): Promise<SealedIdentity> {
  if (!isValidAppKey(appKey)) throw new Error('The app key is not valid.');

  const subtle = crypto.subtle;
  const appPublic = fromBase64Url(appKey);
  const seed =
    overrides.senderSeed ?? crypto.getRandomValues(new Uint8Array(32));
  const nonce: Uint8Array<ArrayBuffer> = overrides.nonce
    ? new Uint8Array(overrides.nonce)
    : crypto.getRandomValues(new Uint8Array(12));

  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + 32);
  pkcs8.set(X25519_PKCS8_PREFIX);
  pkcs8.set(seed, X25519_PKCS8_PREFIX.length);

  const senderPrivate = await subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'X25519' },
    true,
    ['deriveBits'],
  );
  // The public half is the JWK's `x`; WebCrypto has no direct way to ask.
  const jwk = await subtle.exportKey('jwk', senderPrivate);
  const epk = fromBase64Url(jwk.x ?? '');

  const appPublicKey = await subtle.importKey(
    'raw',
    appPublic,
    { name: 'X25519' },
    false,
    [],
  );
  const shared = await subtle.deriveBits(
    { name: 'X25519', public: appPublicKey },
    senderPrivate,
    256,
  );

  const label = new TextEncoder().encode(INFO_LABEL);
  const info = new Uint8Array(label.length + appPublic.length + epk.length);
  info.set(label);
  info.set(appPublic, label.length);
  info.set(epk, label.length + appPublic.length);

  const hkdfKey = await subtle.importKey('raw', shared, 'HKDF', false, [
    'deriveKey',
  ]);
  const aesKey = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );

  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      secret: payload.secret,
      subject: payload.subject,
      drive: payload.drive,
    }),
  );
  const ciphertext = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, plaintext),
  );

  return {
    epk: toBase64Url(epk),
    nonce: toBase64Url(nonce),
    ciphertext: toBase64Url(ciphertext),
  };
}
