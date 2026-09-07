import { del, get, keys, set, update } from 'idb-keyval';

/**
 * Per-agent encryption keys for the local OPFS ClientDb cache.
 *
 * The DbKey is a random 256-bit key that encrypts one agent's local database.
 * It is persisted in two forms:
 *
 * - **Session record** (`atomic.clientdb.session-key.<fingerprint>`): the raw
 *   32 bytes. Exists only while that agent is the device's active session and
 *   is deleted on sign-out. This is what lets a page reload reopen the
 *   encrypted DB without re-entering the secret.
 * - **Wrapped record** (`atomic.clientdb.wrapped-key.<fingerprint>`): the
 *   DbKey encrypted (AES-GCM) under a KEK derived from the agent's private
 *   key. Survives sign-out; only someone who signs in with the agent secret
 *   can unwrap it, so the same agent regains their cache on re-login.
 */

const SESSION_KEY_PREFIX = 'atomic.clientdb.session-key.';
const WRAPPED_KEY_PREFIX = 'atomic.clientdb.wrapped-key.';

const DB_KEY_BYTES = 32;
const IV_BYTES = 12;
const WRAP_FORMAT_VERSION = 1;

// KEK derivation domain separation. Bump the salt version if the scheme ever
// changes; old wrapped records then simply fail to unwrap and are regenerated.
const KEK_SALT = 'atomic.clientdb.kek.v1';
const KEK_INFO_PREFIX = 'clientdb-key-wrap:';

export interface WrappedDbKeyRecord {
  version: number;
  /** AES-GCM IV, base64. */
  iv: string;
  /** The encrypted DbKey, base64. */
  wrapped: string;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

/**
 * Decode base64url (RFC 4648 §5: `-` `_`, possibly unpadded) — the encoding of
 * the private key inside a decoded agent secret.
 */
function base64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
  let normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const remainder = normalized.length % 4;

  if (remainder === 2) {
    normalized += '==';
  } else if (remainder === 3) {
    normalized += '=';
  }

  return base64ToBytes(normalized);
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  return bytes;
}

/**
 * 16-hex-char fingerprint of an agent subject (SHA-256 prefix); used in IDB
 * keys and OPFS db filenames.
 */
export async function agentDbFingerprint(
  agentSubject: string,
): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(agentSubject),
  );

  return Array.from(new Uint8Array(digest).slice(0, 8))
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Derive the key-encryption-key for wrapping an agent's DbKey: HKDF-SHA256
 * over the agent's raw Ed25519 private key, bound to the agent subject via
 * the info parameter.
 */
export async function deriveKek(
  privateKeyBase64url: string,
  agentSubject: string,
): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey(
    'raw',
    base64urlToBytes(privateKeyBase64url),
    'HKDF',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(KEK_SALT),
      info: new TextEncoder().encode(KEK_INFO_PREFIX + agentSubject),
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Encrypt a DbKey under the KEK, producing the persistable wrapped record. */
export async function wrapDbKey(
  kek: CryptoKey,
  dbKey: Uint8Array,
): Promise<{ version: 1; iv: string; wrapped: string }> {
  const iv = randomBytes(IV_BYTES);
  const wrapped = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    kek,
    // Copy into a fresh ArrayBuffer-backed view for SubtleCrypto's
    // `BufferSource`.
    new Uint8Array(dbKey),
  );

  return {
    version: WRAP_FORMAT_VERSION,
    iv: bytesToBase64(iv),
    wrapped: bytesToBase64(new Uint8Array(wrapped)),
  };
}

/**
 * Decrypt a wrapped record back into the raw DbKey. Throws on a wrong KEK
 * (AES-GCM auth-tag failure) or a malformed record.
 */
export async function unwrapDbKey(
  kek: CryptoKey,
  record: { version: number; iv: string; wrapped: string },
): Promise<Uint8Array> {
  if (record.version !== WRAP_FORMAT_VERSION) {
    throw new Error(`Unsupported wrapped DbKey version: ${record.version}`);
  }

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(record.iv) },
    kek,
    base64ToBytes(record.wrapped),
  );
  const dbKey = new Uint8Array(plaintext);

  if (dbKey.length !== DB_KEY_BYTES) {
    throw new Error('Wrapped DbKey record decrypted to the wrong length');
  }

  return dbKey;
}

/** Generate a fresh random 256-bit DbKey. */
export function generateDbKey(): Uint8Array {
  return randomBytes(DB_KEY_BYTES);
}

/** Whether a durable wrapped DbKey record exists for this agent. */
export async function hasWrappedDbKey(agentSubject: string): Promise<boolean> {
  const fingerprint = await agentDbFingerprint(agentSubject);

  return (await get(WRAPPED_KEY_PREFIX + fingerprint)) !== undefined;
}

/** Raw DbKey for the active session, or undefined if none stored. */
export async function getSessionDbKey(
  agentSubject: string,
): Promise<Uint8Array | undefined> {
  const fingerprint = await agentDbFingerprint(agentSubject);

  return (await get(SESSION_KEY_PREFIX + fingerprint)) as
    | Uint8Array
    | undefined;
}

/**
 * Get the existing session key or generate+store a fresh one (used when a DB
 * must open before any secret is available).
 */
export async function getOrCreateSessionDbKey(
  agentSubject: string,
): Promise<Uint8Array> {
  const existing = await getSessionDbKey(agentSubject);

  if (existing) {
    return existing;
  }

  const fingerprint = await agentDbFingerprint(agentSubject);
  // One readwrite transaction also serializes callers in other browser tabs.
  // A read followed by set can hand the worker a key that another caller replaces.
  let dbKey!: Uint8Array;
  await update<Uint8Array>(SESSION_KEY_PREFIX + fingerprint, current => {
    dbKey = current ?? generateDbKey();

    return dbKey;
  });

  return dbKey;
}

/**
 * Called at sign-in, when the raw secret is available.
 *
 * - A wrapped record exists → unwrap it and write it as the session record,
 *   restoring access to the cache from before sign-out.
 * - Only a session record exists (pre-feature upgrade) → wrap it so it also
 *   survives the next sign-out.
 * - Neither exists → generate a fresh DbKey and store both records.
 *
 * A wrapped record that fails to unwrap (corrupt, or wrapped under a
 * different key) is discarded and replaced via the generate path — the cache
 * it protected is unreadable either way.
 */
export async function ensureDbKeyOnSignIn(
  agentSubject: string,
  privateKeyBase64url: string,
): Promise<Uint8Array> {
  const fingerprint = await agentDbFingerprint(agentSubject);
  const kek = await deriveKek(privateKeyBase64url, agentSubject);
  const wrappedRecord = (await get(WRAPPED_KEY_PREFIX + fingerprint)) as
    | WrappedDbKeyRecord
    | undefined;

  if (wrappedRecord) {
    try {
      const dbKey = await unwrapDbKey(kek, wrappedRecord);
      await set(SESSION_KEY_PREFIX + fingerprint, dbKey);

      return dbKey;
    } catch (e) {
      console.warn('Discarding wrapped DbKey record that failed to unwrap:', e);
      await del(WRAPPED_KEY_PREFIX + fingerprint);
    }
  } else {
    // Pre-feature upgrade: a session key exists from before wrapped records
    // did. Wrap it now so this agent's cache survives a sign-out.
    const sessionKey = (await get(SESSION_KEY_PREFIX + fingerprint)) as
      | Uint8Array
      | undefined;

    if (sessionKey) {
      await set(
        WRAPPED_KEY_PREFIX + fingerprint,
        await wrapDbKey(kek, sessionKey),
      );

      return sessionKey;
    }
  }

  const dbKey = await getOrCreateSessionDbKey(agentSubject);
  await set(WRAPPED_KEY_PREFIX + fingerprint, await wrapDbKey(kek, dbKey));

  return dbKey;
}

/**
 * Sign-out: delete every session-key record (any agent, since sign-out ends
 * whichever session was active). Wrapped records stay, so each agent's cache
 * becomes readable again on their next sign-in.
 */
export async function clearSessionDbKeys(): Promise<void> {
  const allKeys = await keys();

  for (const key of allKeys) {
    if (typeof key === 'string' && key.startsWith(SESSION_KEY_PREFIX)) {
      await del(key);
    }
  }
}
