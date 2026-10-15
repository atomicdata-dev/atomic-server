import { del, get, keys, set, update } from 'idb-keyval';
import { encodeB64 } from '@tomic/lib';
import { base64ToBytes, randomBytes } from './bytes';

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
 * - **Wrapped record**: the DbKey encrypted under the agent's credential.
 *   Survives sign-out; only someone who signs in with the agent secret can
 *   unwrap it, so the same agent regains their cache on re-login.
 *
 * ## Wrapped record versions
 *
 * - **v2** (`atomic.clientdb.wrapped-key-v2.<fingerprint>`, written today): a
 *   `SecretEnvelope` from `atomic_lib::vault::secret_envelope` with one
 *   agent-secret wrapper — the same scheme, KEK derivation (BLAKE3 over the
 *   agent's vault proof) and XChaCha20-Poly1305 AEAD as the drive vault keys
 *   `vaultWrapKey` stores in the control plane. Needs the wasm bundle.
 * - **v1** (`atomic.clientdb.wrapped-key.<fingerprint>`, legacy): AES-GCM
 *   under an HKDF-SHA256 KEK derived from the raw Ed25519 private key. Read on
 *   sign-in and rewrapped into v2. Never deleted by the migration, so a
 *   rollback to a build that only knows v1 still opens the cache; it is only
 *   written as a fallback when the wasm bundle cannot load, so the DbKey is
 *   never left without a wrapped copy.
 */

const SESSION_KEY_PREFIX = 'atomic.clientdb.session-key.';
const WRAPPED_KEY_PREFIX = 'atomic.clientdb.wrapped-key.';
const WRAPPED_KEY_V2_PREFIX = 'atomic.clientdb.wrapped-key-v2.';

const DB_KEY_BYTES = 32;
const IV_BYTES = 12;
const WRAP_FORMAT_VERSION = 1;
const WRAP_FORMAT_VERSION_V2 = 2;

// v1 KEK derivation domain separation. Frozen: v1 is read-only legacy.
const KEK_SALT = 'atomic.clientdb.kek.v1';
const KEK_INFO_PREFIX = 'clientdb-key-wrap:';

/** Legacy v1 wrapped record (AES-GCM). */
export interface WrappedDbKeyRecord {
  version: number;
  /** AES-GCM IV, base64. */
  iv: string;
  /** The encrypted DbKey, base64. */
  wrapped: string;
}

/** v2 wrapped record: a `SecretEnvelope` JSON with an agent-secret wrapper. */
export interface WrappedDbKeyRecordV2 {
  version: 2;
  envelope: string;
}

/**
 * The wasm envelope operations v2 records use: `vaultWrapKey` /
 * `vaultUnwrapKey`, the same calls that wrap drive vault keys.
 */
export interface DbKeyWrapOps {
  wrap(dbKey: Uint8Array, vaultProof: Uint8Array): string;
  /** Throws when the proof does not open the envelope. */
  unwrap(envelope: string, vaultProof: Uint8Array): Uint8Array;
}

/** What a sign-in has in hand to open (or create) the wrapped record. */
export interface SignInCredentials {
  /** The raw Ed25519 private key, base64url; opens legacy v1 records. */
  privateKey: string;
  /** The agent's vault proof (`Agent.vaultProofFromSecret`), base64url. */
  vaultProof: string;
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
 * Legacy v1: derive the key-encryption-key for wrapping an agent's DbKey: HKDF-SHA256
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

/**
 * Legacy v1: encrypt a DbKey under the KEK. Only written when the wasm bundle
 * that v2 needs cannot load.
 */
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
    iv: encodeB64(iv),
    wrapped: encodeB64(new Uint8Array(wrapped)),
  };
}

/**
 * Legacy v1: decrypt a wrapped record back into the raw DbKey. Throws on a wrong KEK
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

/** Whether a durable wrapped DbKey record (either version) exists. */
export async function hasWrappedDbKey(agentSubject: string): Promise<boolean> {
  const fingerprint = await agentDbFingerprint(agentSubject);

  return (
    (await get(WRAPPED_KEY_V2_PREFIX + fingerprint)) !== undefined ||
    (await get(WRAPPED_KEY_PREFIX + fingerprint)) !== undefined
  );
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
 * Sign-ins that are preparing an agent's DbKey right now, by agent subject.
 * Settles (never rejects) when that sign-in is done, whatever its outcome.
 */
const signInsInFlight = new Map<string, Promise<void>>();

/**
 * Announce that `work` — a sign-in that ends in {@link ensureDbKeyOnSignIn} —
 * will put this agent's session key in place, so a database opener waits for
 * it instead of giving up. Call it before the first `await` of the sign-in:
 * the opener runs as soon as the agent is set, which can be before the
 * sign-in even starts.
 */
export function trackDbKeySignIn(
  agentSubject: string,
  work: Promise<unknown>,
): void {
  const settled = work.then(
    () => undefined,
    () => undefined,
  );
  signInsInFlight.set(agentSubject, settled);
  void settled.then(() => {
    if (signInsInFlight.get(agentSubject) === settled) {
      signInsInFlight.delete(agentSubject);
    }
  });
}

/**
 * The session key for a database whose wrapped record exists but whose
 * session record does not yet: a sign-in is unwrapping it. Waits for a sign-in
 * announced through {@link trackDbKeySignIn} however long it takes — a v2
 * record needs the wasm bundle, which on a cold page takes seconds — and
 * otherwise polls for up to `timeoutMs` (a sign-in in another tab, or one that
 * was not announced). Undefined when no key appeared.
 */
export async function waitForSessionDbKey(
  agentSubject: string,
  timeoutMs = 3_000,
): Promise<Uint8Array | undefined> {
  for (let waited = 0; waited < timeoutMs; waited += 100) {
    const inFlight = signInsInFlight.get(agentSubject);

    if (inFlight) {
      await inFlight;
    } else {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    const key = await getSessionDbKey(agentSubject);

    if (key) return key;
  }

  return undefined;
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

function decodeVaultProof(vaultProof: string): Uint8Array {
  const proof = base64urlToBytes(vaultProof);

  if (proof.length !== 64) {
    throw new Error(
      `Expected a 64-byte vault proof, got ${proof.length} bytes.`,
    );
  }

  return proof;
}

/**
 * Sign-in awaits this, so a wasm fetch that never settles must not hang it.
 * Timing out counts as "wasm did not load": nothing is discarded.
 */
const WRAP_OPS_LOAD_TIMEOUT_MS = 20_000;

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`timed out after ${ms}ms`)),
      ms,
    );

    promise.then(
      value => {
        clearTimeout(timer);
        resolve(value);
      },
      error => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function loadDefaultWrapOps(): Promise<DbKeyWrapOps> {
  const { loadVaultKeyOps } = await import('./managed/vaultKeyOps');
  const ops = await loadVaultKeyOps();

  return { wrap: ops.vaultWrapKey, unwrap: ops.vaultUnwrapKey };
}

/**
 * Wrap into v2, and prove the envelope opens to the same key before it is
 * stored: a record that cannot be read back is worse than none.
 */
function wrapDbKeyV2(
  ops: DbKeyWrapOps,
  proof: Uint8Array,
  dbKey: Uint8Array,
): WrappedDbKeyRecordV2 {
  const envelope = ops.wrap(dbKey, proof);
  const reopened = ops.unwrap(envelope, proof);

  if (
    reopened.length !== dbKey.length ||
    reopened.some((byte, i) => byte !== dbKey[i])
  ) {
    throw new Error('v2 DbKey envelope did not reopen to the same key');
  }

  return { version: WRAP_FORMAT_VERSION_V2, envelope };
}

/**
 * Called at sign-in, when the raw secret is available.
 *
 * - A v2 record exists → unwrap it into the session record.
 * - Only a v1 record exists → unwrap it, then rewrap it as v2 (the v1 record
 *   stays for rollbacks).
 * - Only a session record exists (pre-feature upgrade) → wrap it so it also
 *   survives the next sign-out.
 * - Nothing exists → generate a fresh DbKey and store both records.
 *
 * A record that fails to unwrap (corrupt, or wrapped under a different key) is
 * discarded and the next version down is tried; with none left a fresh key is
 * generated — the cache it protected is unreadable either way. A v2 record is
 * never discarded because the wasm bundle failed to load: that throws and
 * leaves every record in place, so the next sign-in can retry.
 */
export async function ensureDbKeyOnSignIn(
  agentSubject: string,
  credentials: SignInCredentials,
  loadWrapOps: () => Promise<DbKeyWrapOps> = loadDefaultWrapOps,
): Promise<Uint8Array> {
  const fingerprint = await agentDbFingerprint(agentSubject);
  const proof = decodeVaultProof(credentials.vaultProof);
  const v2Key = WRAPPED_KEY_V2_PREFIX + fingerprint;
  const v1Key = WRAPPED_KEY_PREFIX + fingerprint;

  let ops: DbKeyWrapOps | undefined;
  let opsError: unknown;

  try {
    ops = await withTimeout(loadWrapOps(), WRAP_OPS_LOAD_TIMEOUT_MS);
  } catch (e) {
    opsError = e;
  }

  const v2Record = (await get(v2Key)) as WrappedDbKeyRecordV2 | undefined;

  if (v2Record) {
    if (!ops) {
      throw new Error(
        'Cannot unwrap the local database key: the wasm bundle did not load.',
        { cause: opsError },
      );
    }

    try {
      const dbKey = ops.unwrap(v2Record.envelope, proof);

      if (dbKey.length !== DB_KEY_BYTES) {
        throw new Error('Wrapped DbKey envelope held the wrong length');
      }

      await set(SESSION_KEY_PREFIX + fingerprint, dbKey);

      return dbKey;
    } catch (e) {
      console.warn('Discarding v2 DbKey record that failed to unwrap:', e);
      await del(v2Key);
    }
  }

  if (!ops) {
    console.warn(
      'Local database key falls back to the legacy wrapping: wasm did not load.',
      opsError,
    );
  }

  // Only v1 needs it, and it needs WebCrypto: derived on demand.
  const kek = () => deriveKek(credentials.privateKey, agentSubject);

  /** Store the wrapped copy: v2 when possible, v1 only without wasm. */
  const persistWrapped = async (dbKey: Uint8Array) => {
    if (ops) {
      await set(v2Key, wrapDbKeyV2(ops, proof, dbKey));
    } else {
      await set(v1Key, await wrapDbKey(await kek(), dbKey));
    }
  };

  const v1Record = (await get(v1Key)) as WrappedDbKeyRecord | undefined;

  if (v1Record) {
    let dbKey: Uint8Array | undefined;

    try {
      dbKey = await unwrapDbKey(await kek(), v1Record);
    } catch (e) {
      console.warn('Discarding v1 DbKey record that failed to unwrap:', e);
      await del(v1Key);
    }

    if (dbKey) {
      // Session first: the cache opens even if the rewrap below fails.
      await set(SESSION_KEY_PREFIX + fingerprint, dbKey);

      if (ops) {
        try {
          await set(v2Key, wrapDbKeyV2(ops, proof, dbKey));
        } catch (e) {
          // The v1 record still holds the key; the next sign-in retries.
          console.warn('Failed to rewrap DbKey as v2:', e);
        }
      }

      return dbKey;
    }
  } else if (!v2Record) {
    // Pre-feature upgrade: a session key exists from before wrapped records
    // did. Wrap it now so this agent's cache survives a sign-out.
    const sessionKey = (await get(SESSION_KEY_PREFIX + fingerprint)) as
      | Uint8Array
      | undefined;

    if (sessionKey) {
      await persistWrapped(sessionKey);

      return sessionKey;
    }
  }

  const dbKey = await getOrCreateSessionDbKey(agentSubject);
  await persistWrapped(dbKey);

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
