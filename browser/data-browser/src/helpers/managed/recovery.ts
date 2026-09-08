import { getManagedAccount } from './session';
import { isRunningInTauri } from '../tauri';
import { wasmBinaryUrl, wasmJsUrl } from '../wasmUrls';
import { PRODUCT_NAME } from './product';
import { managedFetch } from './api';
import { writeManagedAccountBinding } from './binding';

export type RecoveryWrapperInput = {
  wrapper_type: 'webauthn-prf' | 'recovery-code';
  /** Empty for `webauthn-prf`: the authenticator's PRF output *is* the KEK. */
  kdf_algorithm: string;
  kdf_params: Record<string, unknown>;
  /** KDF salt for a code wrapper; the PRF evaluation input for a passkey. */
  salt: string;
  wrapped_dek: string;
  wrap_nonce: string;
  /** `webauthn-prf` only: base64 of the credential's raw id. */
  credential_id?: string | null;
  label?: string | null;
};

export type RecoveryWrapper = RecoveryWrapperInput & {
  created_at: number;
};

export type RecoverySecretInput = {
  agent_subject: string;
  drive_subject?: string | null;
  encrypted_secret: string;
  encryption_algorithm: string;
  // v1 only; envelope-v2 requests omit these and rely on `wrappers` instead
  // (the server mirrors the primary wrapper's KDF at the top level itself).
  kdf_algorithm?: string;
  kdf_params?: Record<string, unknown>;
  salt?: string;
  nonce: string;
  format_version: number;
  wrappers?: RecoveryWrapperInput[];
};

export type RecoverySecret = {
  owner_email: string;
  agent_subject: string;
  drive_subject?: string | null;
  encrypted_secret: string;
  encryption_algorithm: string;
  kdf_algorithm: string;
  kdf_params: Record<string, unknown>;
  salt: string;
  nonce: string;
  format_version: number;
  wrappers: RecoveryWrapper[];
  created_at: number;
  updated_at: number;
};

const RECOVERY_FORMAT_VERSION = 1;
const ENVELOPE_V2_FORMAT_VERSION = 2;
const KDF_ITERATIONS = 310_000;
const KDF_HASH = 'SHA-256';
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const DEK_BYTES = 32;

// Argon2id defaults for the envelope-v2 recovery-code wrapper. ~64 MiB / 3
// iterations / 1 lane: memory-hard enough that GPU parallelism doesn't help
// an attacker the way it does against PBKDF2, while staying well under a
// second to decrypt on low-end mobile. Stored per-wrapper alongside the blob
// so these can evolve without a format change (planning/BACKUP_SECURITY.md
// open question #5).
const ARGON2_MEM_KIB = 64 * 1024;
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 1;

// Crockford's Base32 (excludes I, L, O, U to avoid confusion with 1/0/V) —
// chosen for the generated recovery code so it's typo-tolerant to type or
// read aloud. 5 groups of 5 chars = 25 chars = 125 bits, generated from 16
// random bytes (128 bits). planning/BACKUP_SECURITY.md open question #1.
const RECOVERY_CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const RECOVERY_CODE_GROUP_LEN = 5;
const RECOVERY_CODE_GROUPS = 5;
const RECOVERY_CODE_CHARS = RECOVERY_CODE_GROUP_LEN * RECOVERY_CODE_GROUPS;
const RECOVERY_CODE_BYTES = Math.ceil((RECOVERY_CODE_CHARS * 5) / 8);

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

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  return bytes;
}

/** Generate a machine-strength recovery code, e.g. `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`. */
export function generateRecoveryCode(): string {
  const bytes = randomBytes(RECOVERY_CODE_BYTES);
  let value = 0;
  let bits = 0;
  let output = '';

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      bits -= 5;
      output += RECOVERY_CODE_ALPHABET[(value >>> bits) & 0x1f];
    }

    value &= (1 << bits) - 1;
  }

  output = output.slice(0, RECOVERY_CODE_CHARS);

  const groups: string[] = [];

  for (let i = 0; i < output.length; i += RECOVERY_CODE_GROUP_LEN) {
    groups.push(output.slice(i, i + RECOVERY_CODE_GROUP_LEN));
  }

  return groups.join('-');
}

/**
 * Canonical KDF input for a recovery code: uppercased, dashes/whitespace
 * stripped, and the characters Crockford's Base32 deliberately excludes
 * mapped back to the ones they're confused with (O -> 0, I/L -> 1).
 *
 * Both wrapping and unwrapping run the code through this, so the grouped
 * display form (`XXXXX-XXXXX-…`) is presentation only and a user may type it
 * with or without the dashes. Deriving from the *displayed* form instead
 * would mean a correctly-typed code failed to decrypt.
 */
export function normalizeRecoveryCodeInput(input: string): string {
  return input
    .toUpperCase()
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')
    .replace(/[^0-9A-Z]/g, '');
}

// --- Envelope v1 (legacy, password-wrapped) ---

async function deriveRecoveryKey(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle?.importKey) {
    throw new Error('This browser does not support encrypted recovery.');
  }

  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: KDF_ITERATIONS,
      hash: KDF_HASH,
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}

export async function buildEncryptedRecoverySecret({
  secret,
  password,
  agentSubject,
  driveSubject,
}: {
  secret: string;
  password: string;
  agentSubject: string;
  driveSubject?: string | null;
}): Promise<RecoverySecretInput> {
  const salt = randomBytes(SALT_BYTES);
  const nonce = randomBytes(NONCE_BYTES);
  const key = await deriveRecoveryKey(password, salt, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    new TextEncoder().encode(secret),
  );

  return {
    agent_subject: agentSubject,
    drive_subject: driveSubject ?? null,
    encrypted_secret: bytesToBase64(new Uint8Array(ciphertext)),
    encryption_algorithm: 'AES-GCM',
    kdf_algorithm: 'PBKDF2',
    kdf_params: {
      hash: KDF_HASH,
      iterations: KDF_ITERATIONS,
    },
    salt: bytesToBase64(salt),
    nonce: bytesToBase64(nonce),
    format_version: RECOVERY_FORMAT_VERSION,
  };
}

/**
 * Reverse of {@link buildEncryptedRecoverySecret}: derive the AES-GCM key from
 * the recovery password + stored salt, then decrypt the agent secret. Throws a
 * friendly error on a wrong password (AES-GCM auth-tag failure).
 */
export async function decryptRecoverySecret(
  recovery: RecoverySecret,
  password: string,
): Promise<string> {
  const salt = base64ToBytes(recovery.salt);
  const nonce = base64ToBytes(recovery.nonce);
  const key = await deriveRecoveryKey(password, salt, ['decrypt']);

  let plaintext: ArrayBuffer;

  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      base64ToBytes(recovery.encrypted_secret),
    );
  } catch {
    throw new Error('Wrong recovery password');
  }

  return new TextDecoder().decode(plaintext);
}

// --- Envelope v2 (DEK + recovery-code wrapper via Argon2id) ---

type Argon2WasmModule = {
  default: (init?: { module_or_path: string }) => Promise<unknown>;
  argon2idDeriveKey: (
    secret: string,
    salt: Uint8Array,
    memKib: number,
    iterations: number,
    parallelism: number,
  ) => Uint8Array;
};

/** What the dynamic import actually gives us: an older build of the glue has
 * `default` but not the KDF, which is the case {@link loadArgon2Wasm} checks. */
type LoadedWasmModule = Partial<Argon2WasmModule> &
  Pick<Argon2WasmModule, 'default'>;

let argon2ModulePromise: Promise<Argon2WasmModule> | null = null;

/**
 * Lazily loads the atomic_wasm bundle on the main thread, independent of the
 * ClientDb worker (initClientDb.ts) — this is a stateless KDF call, not a
 * database, so it doesn't need OPFS or worker/leader-election machinery.
 *
 * The export is verified rather than assumed. A page that spans a deploy can
 * hold a module from an older build (see `helpers/wasmUrls.ts`), where calling
 * the missing KDF surfaces as a bare "is not a function" TypeError halfway
 * through generating a recovery code. Failing here instead says what to do.
 */
async function loadArgon2Wasm(): Promise<Argon2WasmModule> {
  if (!argon2ModulePromise) {
    argon2ModulePromise = (async () => {
      try {
        const url = wasmJsUrl();
        const loaded = (await import(
          /* @vite-ignore */ url
        )) as LoadedWasmModule;
        await loaded.default({ module_or_path: wasmBinaryUrl() });

        if (typeof loaded.argon2idDeriveKey !== 'function') {
          throw new Error(
            'This page is running an outdated version of Atomic. Reload the page and try again.',
          );
        }

        return loaded as Argon2WasmModule;
      } catch (e) {
        // Never memoize a failure: after the reload this asks for, and for an
        // offline blip on the way to a 6MB binary, a retry must be able to
        // load it rather than replay the rejection for the tab's lifetime.
        argon2ModulePromise = null;
        throw e;
      }
    })();
  }

  return argon2ModulePromise;
}

async function deriveKeyFromRecoveryCode(
  code: string,
  salt: Uint8Array,
  usages: KeyUsage[],
  kdfParams?: Record<string, unknown>,
): Promise<CryptoKey> {
  const wasm = await loadArgon2Wasm();
  const memKib = Number(kdfParams?.mem_kib ?? ARGON2_MEM_KIB);
  const iterations = Number(kdfParams?.iterations ?? ARGON2_ITERATIONS);
  const parallelism = Number(kdfParams?.parallelism ?? ARGON2_PARALLELISM);
  const kek = wasm.argon2idDeriveKey(
    code,
    salt,
    memKib,
    iterations,
    parallelism,
  );

  return crypto.subtle.importKey(
    'raw',
    new Uint8Array(kek),
    'AES-GCM',
    false,
    usages,
  );
}

// --- WebAuthn PRF wrapper (the default: nothing for the user to store) ---

/**
 * The `prf` extension isn't in TypeScript's DOM lib yet, so the shapes we
 * rely on are declared here rather than cast away at each call site.
 */
type PrfExtensionOutputs = {
  prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } };
};

/** How long to wait for the user's authenticator before giving up. */
const WEBAUTHN_TIMEOUT_MS = 60_000;

/**
 * The Relying Party the recovery passkey belongs to.
 *
 * The parent domain, not the app host, so one credential works from both the
 * portal (`atomicserver.eu`) and the app (`app.atomicserver.eu`) — an RP ID may
 * be any registrable-domain suffix of the origin. It must match
 * `webcredentials:` in the iOS entitlement and the `apple-app-site-association`
 * served by that domain.
 */
const PASSKEY_RP_ID = 'atomicserver.eu';

/**
 * The `rp.id` to use here, or `undefined` to let the browser default to the
 * origin's effective domain.
 *
 * This used to be omitted everywhere, on the reasoning that the default is
 * right in both dev and production. That holds in a browser but breaks in the
 * Tauri app: the webview serves from `tauri://localhost` (macOS/iOS) or
 * `http://tauri.localhost` (Windows/Android), neither of which is a registrable
 * domain, so there is no effective domain to default to and the ceremony fails.
 * Naming the RP explicitly is what lets the Associated Domains entitlement
 * vouch for the app.
 *
 * Returning `undefined` on plain localhost is deliberate rather than lazy:
 * `rp.id` must be a suffix of the origin's domain, so naming a real domain
 * during local dev throws SecurityError. Dev passkeys stay bound to localhost,
 * which is correct — they are not meant to unlock production backups.
 */
export function passkeyRpId(): string | undefined {
  if (typeof window === 'undefined') return undefined;

  const host = window.location.hostname;

  if (host === PASSKEY_RP_ID || host.endsWith(`.${PASSKEY_RP_ID}`)) {
    return PASSKEY_RP_ID;
  }

  // Tauri's hostname is also literally "localhost", so the check above cannot
  // tell the app apart from local dev — this has to come after it.
  return isRunningInTauri() ? PASSKEY_RP_ID : undefined;
}

/** Thrown when this browser/authenticator can't do PRF — the caller should
 * fall back to the generated-code wrapper rather than surface an error. */
export class PrfUnsupportedError extends Error {
  constructor(message = 'This device cannot protect a backup with a passkey.') {
    super(message);
    this.name = 'PrfUnsupportedError';
  }
}

/**
 * Whether to offer the passkey path at all. `getClientCapabilities` answers
 * directly where it exists; otherwise the presence of a platform
 * authenticator is the best available proxy — actual PRF support can only be
 * confirmed by registering, which is why {@link registerPasskeyWrapper}
 * re-checks and throws {@link PrfUnsupportedError} if it turns out to be
 * missing.
 */
export async function isPasskeySupported(): Promise<boolean> {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) {
    return false;
  }

  const withCapabilities = PublicKeyCredential as typeof PublicKeyCredential & {
    getClientCapabilities?: () => Promise<Record<string, boolean | undefined>>;
  };

  if (typeof withCapabilities.getClientCapabilities === 'function') {
    try {
      const capabilities = await withCapabilities.getClientCapabilities();

      if (typeof capabilities?.prf === 'boolean') {
        return capabilities.prf;
      }
    } catch {
      // Fall through to the platform-authenticator probe below.
    }
  }

  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/** The PRF output is already uniform 32 bytes, so it's the KEK directly. */
function importPrfKey(
  output: ArrayBuffer,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new Uint8Array(output),
    'AES-GCM',
    false,
    usages,
  );
}

/**
 * Evaluate a credential's PRF for `salt` — one authenticator prompt.
 *
 * The challenge is random client-side bytes rather than a server-issued one,
 * and nothing verifies the assertion — deliberately. This is not
 * authentication: the security property is "only the authenticator holding
 * this credential can reproduce this PRF output", which holds regardless of
 * challenge freshness. A forged assertion yields a KEK that fails to unwrap
 * the DEK, and AES-GCM's auth tag catches it locally. That's also why no
 * server-side WebAuthn ceremony exists for this.
 */
async function evaluatePrf(
  credentialId: Uint8Array,
  salt: Uint8Array,
): Promise<ArrayBuffer> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      // Must name the same RP the credential was created under, for the same
      // reason `create` does — see {@link passkeyRpId}. An assertion whose
      // rpId does not match the one in the credential is simply not found.
      rpId: passkeyRpId(),
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      userVerification: 'required',
      // Without this the browser's own (multi-minute) default applies, and a
      // device the passkey never synced to just sits there: no prompt to
      // answer, no error, a permanently pending button. Bounded so the user
      // gets a real failure they can act on.
      timeout: WEBAUTHN_TIMEOUT_MS,
      extensions: { prf: { eval: { first: salt } } },
    },
  } as CredentialRequestOptions)) as PublicKeyCredential | null;

  if (!assertion) {
    throw new PrfUnsupportedError('No passkey was provided.');
  }

  const results = (assertion.getClientExtensionResults() as PrfExtensionOutputs)
    .prf?.results?.first;

  if (!results) {
    throw new PrfUnsupportedError(
      'This passkey did not return the key material needed to unlock the backup.',
    );
  }

  return results;
}

async function derivePrfKey(
  credentialId: Uint8Array,
  salt: Uint8Array,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  return importPrfKey(await evaluatePrf(credentialId, salt), usages);
}

/**
 * Whether the new credential is a *synced* passkey (iCloud Keychain, Google
 * Password Manager) or bound to this one device.
 *
 * Read from the BE ("backup eligible") bit of the authenticator data flags:
 * byte 32, mask 0x08. It matters because it's the difference between "lose
 * this laptop and your passkey reappears on the next one" and "lose this
 * laptop and your identity is gone" — only the latter warrants pushing a
 * recovery code at the user.
 *
 * `unknown` when the browser doesn't expose `getAuthenticatorData()`. Treated
 * as synced by callers (no nag): guessing device-bound would put the extra
 * step in front of everyone on older browsers, which is the friction this
 * whole flow exists to remove.
 */
export type PasskeyDurability = 'synced' | 'device-bound' | 'unknown';

function readPasskeyDurability(
  response: AuthenticatorAttestationResponse,
): PasskeyDurability {
  const withAuthData = response as AuthenticatorAttestationResponse & {
    getAuthenticatorData?: () => ArrayBuffer;
  };

  if (typeof withAuthData.getAuthenticatorData !== 'function') {
    return 'unknown';
  }

  try {
    const authData = new Uint8Array(withAuthData.getAuthenticatorData());

    // rpIdHash (32) then the flags byte.
    if (authData.length < 33) return 'unknown';

    const BACKUP_ELIGIBLE = 0x08;

    return (authData[32] & BACKUP_ELIGIBLE) !== 0 ? 'synced' : 'device-bound';
  } catch {
    return 'unknown';
  }
}

/**
 * Register a new passkey and wrap `dek` with its PRF output.
 *
 * The PRF evaluation is requested *during* creation, so enrolling costs a
 * single authenticator prompt on browsers that support it (Level 3 behaviour
 * — Chrome and Safari both do). Older ones only report `enabled` at creation
 * without evaluating, and those alone pay for a second prompt via the
 * `evaluatePrf` fallback below. Unlocking later is always one prompt.
 */
async function wrapDekWithPasskey(
  dek: Uint8Array<ArrayBuffer>,
  { userName, userDisplayName }: { userName: string; userDisplayName: string },
): Promise<{ wrapper: RecoveryWrapperInput; durability: PasskeyDurability }> {
  // Generated up front so the same salt can be evaluated at creation time.
  const prfSalt = randomBytes(SALT_BYTES);

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: { name: PRODUCT_NAME, id: passkeyRpId() },
      user: {
        // Opaque by design — we never do discoverable-credential login, so
        // this identifies nothing and leaks nothing.
        id: randomBytes(32),
        name: userName,
        displayName: userDisplayName,
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        // PRF requires user verification.
        userVerification: 'required',
      },
      timeout: WEBAUTHN_TIMEOUT_MS,
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  } as CredentialCreationOptions)) as PublicKeyCredential | null;

  if (!credential) {
    throw new PrfUnsupportedError('Passkey creation was cancelled.');
  }

  const created = credential.getClientExtensionResults() as PrfExtensionOutputs;

  if (created.prf?.enabled === false) {
    throw new PrfUnsupportedError();
  }

  const credentialId = new Uint8Array(credential.rawId);
  const wrapNonce = randomBytes(NONCE_BYTES);
  // Present on browsers that evaluate PRF at creation; otherwise fall back to
  // a second prompt. Either way the salt (and so the KEK) is identical.
  const prfOutput =
    created.prf?.results?.first ?? (await evaluatePrf(credentialId, prfSalt));
  const wrapKey = await importPrfKey(prfOutput, ['encrypt']);
  const wrappedDek = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: wrapNonce },
    wrapKey,
    dek,
  );

  const durability = readPasskeyDurability(
    credential.response as AuthenticatorAttestationResponse,
  );

  return {
    durability,
    wrapper: {
      wrapper_type: 'webauthn-prf',
      kdf_algorithm: '',
      kdf_params: {},
      salt: bytesToBase64(prfSalt),
      wrapped_dek: bytesToBase64(new Uint8Array(wrappedDek)),
      wrap_nonce: bytesToBase64(wrapNonce),
      credential_id: bytesToBase64(credentialId),
      label: `Passkey added ${new Date().toISOString().slice(0, 10)}`,
    },
  };
}

// --- Envelope v2 assembly ---

/** Encrypt the agent secret once under a fresh random DEK. */
async function sealSecret(secret: string): Promise<{
  dek: Uint8Array<ArrayBuffer>;
  encryptedSecret: string;
  nonce: string;
}> {
  const dek = randomBytes(DEK_BYTES);
  const dekKey = await crypto.subtle.importKey('raw', dek, 'AES-GCM', false, [
    'encrypt',
  ]);
  const secretNonce = randomBytes(NONCE_BYTES);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: secretNonce },
    dekKey,
    new TextEncoder().encode(secret),
  );

  return {
    dek,
    encryptedSecret: bytesToBase64(new Uint8Array(ciphertext)),
    nonce: bytesToBase64(secretNonce),
  };
}

async function wrapDekWithCode(
  dek: Uint8Array<ArrayBuffer>,
  recoveryCode: string,
): Promise<RecoveryWrapperInput> {
  const wrapperSalt = randomBytes(SALT_BYTES);
  const wrapNonce = randomBytes(NONCE_BYTES);
  const kdfParams = {
    mem_kib: ARGON2_MEM_KIB,
    iterations: ARGON2_ITERATIONS,
    parallelism: ARGON2_PARALLELISM,
  };
  const wrapKey = await deriveKeyFromRecoveryCode(
    // Always the normalized form — see normalizeRecoveryCodeInput.
    normalizeRecoveryCodeInput(recoveryCode),
    wrapperSalt,
    ['encrypt'],
    kdfParams,
  );
  const wrappedDek = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: wrapNonce },
    wrapKey,
    dek,
  );

  return {
    wrapper_type: 'recovery-code',
    kdf_algorithm: 'argon2id',
    kdf_params: kdfParams,
    salt: bytesToBase64(wrapperSalt),
    wrapped_dek: bytesToBase64(new Uint8Array(wrappedDek)),
    wrap_nonce: bytesToBase64(wrapNonce),
    label: `Recovery code saved ${new Date().toISOString().slice(0, 10)}`,
  };
}

function envelopeRequest({
  agentSubject,
  driveSubject,
  sealed,
  wrappers,
}: {
  agentSubject: string;
  driveSubject?: string | null;
  sealed: { encryptedSecret: string; nonce: string };
  wrappers: RecoveryWrapperInput[];
}): RecoverySecretInput {
  return {
    agent_subject: agentSubject,
    drive_subject: driveSubject ?? null,
    encrypted_secret: sealed.encryptedSecret,
    encryption_algorithm: 'AES-GCM',
    nonce: sealed.nonce,
    format_version: ENVELOPE_V2_FORMAT_VERSION,
    wrappers,
  };
}

/**
 * The default backup path: seal the secret under a DEK wrapped by a newly
 * registered passkey. Nothing is returned for the user to store — that's the
 * point. Throws {@link PrfUnsupportedError} when the authenticator can't do
 * PRF, so the caller can fall back to {@link buildEnvelopeV2}.
 */
export async function buildEnvelopeWithPasskey({
  secret,
  agentSubject,
  driveSubject,
  userName,
  userDisplayName,
}: {
  secret: string;
  agentSubject: string;
  driveSubject?: string | null;
  userName: string;
  userDisplayName?: string;
}): Promise<{ request: RecoverySecretInput; durability: PasskeyDurability }> {
  const sealed = await sealSecret(secret);
  const { wrapper, durability } = await wrapDekWithPasskey(sealed.dek, {
    userName,
    userDisplayName: userDisplayName ?? userName,
  });

  return {
    durability,
    request: envelopeRequest({
      agentSubject,
      driveSubject,
      sealed,
      wrappers: [wrapper],
    }),
  };
}

/**
 * Seal `secret` under BOTH a new passkey and a generated recovery code. For
 * the device-bound-passkey case, where the passkey alone genuinely is a
 * single point of failure.
 */
export async function buildEnvelopeWithPasskeyAndCode({
  secret,
  agentSubject,
  driveSubject,
  userName,
}: {
  secret: string;
  agentSubject: string;
  driveSubject?: string | null;
  userName: string;
}): Promise<{ request: RecoverySecretInput; recoveryCode: string }> {
  const sealed = await sealSecret(secret);
  const { wrapper: passkeyWrapper } = await wrapDekWithPasskey(sealed.dek, {
    userName,
    userDisplayName: userName,
  });
  const recoveryCode = generateRecoveryCode();
  const codeWrapper = await wrapDekWithCode(sealed.dek, recoveryCode);

  return {
    recoveryCode,
    request: envelopeRequest({
      agentSubject,
      driveSubject,
      sealed,
      wrappers: [passkeyWrapper, codeWrapper],
    }),
  };
}

/**
 * The fallback backup path: seal the secret under a DEK wrapped by a freshly
 * generated recovery code. Returns the plaintext code so the caller can show
 * it once — neither it nor the DEK are ever sent to SaaS.
 */
export async function buildEnvelopeV2({
  secret,
  agentSubject,
  driveSubject,
}: {
  secret: string;
  agentSubject: string;
  driveSubject?: string | null;
}): Promise<{ recoveryCode: string; request: RecoverySecretInput }> {
  const sealed = await sealSecret(secret);
  const recoveryCode = generateRecoveryCode();
  const wrapper = await wrapDekWithCode(sealed.dek, recoveryCode);

  return {
    recoveryCode,
    request: envelopeRequest({
      agentSubject,
      driveSubject,
      sealed,
      wrappers: [wrapper],
    }),
  };
}

/** Whether this backup can be unlocked by a passkey / by a typed code. */
export function envelopeWrapperKinds(recovery: RecoverySecret): {
  hasPasskey: boolean;
  hasCode: boolean;
} {
  return {
    hasPasskey: recovery.wrappers.some(w => w.wrapper_type === 'webauthn-prf'),
    hasCode: recovery.wrappers.some(w => w.wrapper_type === 'recovery-code'),
  };
}

async function openWithDekKey(
  recovery: RecoverySecret,
  wrapper: RecoveryWrapper,
  wrapKey: CryptoKey,
  wrongKeyMessage: string,
): Promise<string> {
  let plaintext: ArrayBuffer;

  try {
    const dek = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(wrapper.wrap_nonce) },
      wrapKey,
      base64ToBytes(wrapper.wrapped_dek),
    );
    const dekKey = await crypto.subtle.importKey('raw', dek, 'AES-GCM', false, [
      'decrypt',
    ]);
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(recovery.nonce) },
      dekKey,
      base64ToBytes(recovery.encrypted_secret),
    );
  } catch {
    throw new Error(wrongKeyMessage);
  }

  return new TextDecoder().decode(plaintext);
}

/** Unlock a v2 backup with its registered passkey (one biometric prompt). */
export async function decryptEnvelopeWithPasskey(
  recovery: RecoverySecret,
): Promise<string> {
  const wrapper = recovery.wrappers.find(
    w => w.wrapper_type === 'webauthn-prf' && w.credential_id,
  );

  if (!wrapper?.credential_id) {
    throw new Error('This backup has no passkey.');
  }

  const wrapKey = await derivePrfKey(
    base64ToBytes(wrapper.credential_id),
    base64ToBytes(wrapper.salt),
    ['decrypt'],
  );

  return openWithDekKey(
    recovery,
    wrapper,
    wrapKey,
    'That passkey could not unlock this backup.',
  );
}

/**
 * Reverse of {@link buildEnvelopeV2}: unwrap the DEK with the recovery code,
 * then decrypt the agent secret. Throws a friendly error on a wrong code
 * (AES-GCM auth-tag failure on either step).
 */
export async function decryptEnvelopeV2(
  recovery: RecoverySecret,
  recoveryCode: string,
): Promise<string> {
  const wrapper = recovery.wrappers.find(
    w => w.wrapper_type === 'recovery-code',
  );

  if (!wrapper) {
    throw new Error('This backup has no recovery-code wrapper.');
  }

  const wrapKey = await deriveKeyFromRecoveryCode(
    // Normalized here too, so callers may pass exactly what the user typed.
    normalizeRecoveryCodeInput(recoveryCode),
    base64ToBytes(wrapper.salt),
    ['decrypt'],
    wrapper.kdf_params,
  );

  return openWithDekKey(recovery, wrapper, wrapKey, 'Wrong recovery code');
}

/**
 * Recover the plaintext agent secret from the stored backup.
 *
 * The local keypair is stored non-extractably (see `agentStorage.ts`), so
 * this blob — not IndexedDB — is what makes the secret showable again. Costs
 * one passkey prompt, or the recovery code if that's the only wrapper.
 * Returns null when no backup exists, in which case the secret genuinely is
 * unrecoverable and the caller should say so.
 */
export async function revealSecretFromBackup(
  recoveryCode?: string,
  agentSubject?: string,
): Promise<string | null> {
  // Cache-aware, like the card that offers this action: after unlocking with
  // a passkey there is no portal session, so a server-only read would 401 and
  // claim there's no backup — while the passkey sits right there, able to
  // decrypt it.
  const recovery = await getUnlockableRecoverySecret(agentSubject);

  if (!recovery) return null;

  const { hasPasskey, hasCode } = envelopeWrapperKinds(recovery);

  if (hasPasskey && !recoveryCode) {
    return decryptEnvelopeWithPasskey(recovery);
  }

  if (recoveryCode) {
    return recovery.format_version >= 2
      ? decryptEnvelopeV2(recovery, recoveryCode)
      : decryptRecoverySecret(recovery, recoveryCode);
  }

  if (hasCode || recovery.format_version < 2) {
    throw new Error(
      recovery.format_version < 2
        ? 'Enter your recovery password to show your secret.'
        : 'Enter your recovery code to show your secret.',
    );
  }

  throw new Error('This backup has no usable wrapper.');
}

/**
 * Add a recovery-code wrapper to an existing backup, keeping the current
 * wrappers intact.
 *
 * Unwraps the same DEK via the passkey and re-wraps it under a new code, so
 * both credentials open the same ciphertext — no plaintext agent secret is
 * needed, and existing passkeys keep working. This is the escape hatch for
 * someone who enrolled with only a passkey and later wants an offline copy.
 */
export async function addRecoveryCodeWrapper(agentSubject?: string): Promise<{
  recoveryCode: string;
  saved: RecoverySecret;
}> {
  // Reads work from the cache; the *write* below still needs a portal session,
  // and `saveRecoverySecret` says so specifically on a 401.
  const recovery = await getUnlockableRecoverySecret(agentSubject);

  if (!recovery) {
    throw new Error('There is no backup to add a recovery code to.');
  }

  const passkeyWrapper = recovery.wrappers.find(
    w => w.wrapper_type === 'webauthn-prf' && w.credential_id,
  );

  if (!passkeyWrapper?.credential_id) {
    throw new Error('Adding a recovery code needs an existing passkey.');
  }

  // Unwrap the DEK itself (not the secret) so every existing wrapper keeps
  // opening the same ciphertext.
  const prfKey = await derivePrfKey(
    base64ToBytes(passkeyWrapper.credential_id),
    base64ToBytes(passkeyWrapper.salt),
    ['decrypt'],
  );

  let dek: ArrayBuffer;

  try {
    dek = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(passkeyWrapper.wrap_nonce) },
      prfKey,
      base64ToBytes(passkeyWrapper.wrapped_dek),
    );
  } catch {
    throw new Error('That passkey could not unlock this backup.');
  }

  const recoveryCode = generateRecoveryCode();
  const codeWrapper = await wrapDekWithCode(new Uint8Array(dek), recoveryCode);

  const saved = await saveRecoverySecret({
    agent_subject: recovery.agent_subject,
    drive_subject: recovery.drive_subject ?? null,
    encrypted_secret: recovery.encrypted_secret,
    encryption_algorithm: recovery.encryption_algorithm,
    nonce: recovery.nonce,
    format_version: ENVELOPE_V2_FORMAT_VERSION,
    wrappers: [
      ...recovery.wrappers
        .filter(w => w.wrapper_type !== 'recovery-code')
        .map(({ created_at: _created, ...rest }) => rest),
      codeWrapper,
    ],
  });

  return { recoveryCode, saved };
}

/**
 * Upload a sealed backup this device is holding on its own.
 *
 * The envelope is already built, so this needs no secret, no passkey and no
 * new code: it is the same ciphertext, put where an email can reach it. That
 * gap is real rather than theoretical — a browser keeps its cached copy when
 * the control plane loses the row (a reset dev database, an account moved
 * between deployments), and until this the only way back was
 * `addRecoveryCodeWrapper`, which re-uploads as a side effect of demanding a
 * passkey tap and handing back a code nobody asked for.
 */
export async function storeCachedRecoverySecret(
  recovery: RecoverySecret,
): Promise<RecoverySecret> {
  const base = {
    agent_subject: recovery.agent_subject,
    drive_subject: recovery.drive_subject ?? null,
    encrypted_secret: recovery.encrypted_secret,
    encryption_algorithm: recovery.encryption_algorithm,
    nonce: recovery.nonce,
    format_version: recovery.format_version,
  };

  // A v1 row carries its KDF at the top level and must send no wrappers; v2
  // is the other way round. Re-deriving either shape would be inventing
  // crypto, so send back exactly what was stored.
  return saveRecoverySecret(
    recovery.format_version === RECOVERY_FORMAT_VERSION
      ? {
          ...base,
          kdf_algorithm: recovery.kdf_algorithm,
          kdf_params: recovery.kdf_params,
          salt: recovery.salt,
        }
      : {
          ...base,
          wrappers: recovery.wrappers.map(
            ({ created_at: _created, ...rest }) => rest,
          ),
        },
  );
}

/**
 * Lazy migration for a v1 row: re-encrypt under envelope v2 and replace the
 * stored blob, after a successful v1 decrypt (sign-in or restore) — never
 * forced. Prefers a passkey, so the common case needs no new screen and
 * leaves the user nothing extra to keep; only a device that can't do PRF
 * falls back to a generated code (which the caller must then show once).
 * See planning/BACKUP_SECURITY.md's migration section.
 */
export async function upgradeToEnvelopeV2({
  secret,
  agentSubject,
  driveSubject,
  userName,
}: {
  secret: string;
  agentSubject: string;
  driveSubject?: string | null;
  userName: string;
}): Promise<{ recoveryCode: string | null; saved: RecoverySecret }> {
  if (await isPasskeySupported()) {
    try {
      const { request } = await buildEnvelopeWithPasskey({
        secret,
        agentSubject,
        driveSubject,
        userName,
      });

      return { recoveryCode: null, saved: await saveRecoverySecret(request) };
    } catch (e) {
      // A cancelled prompt is a deliberate "not now" — don't silently mint a
      // recovery code the user never asked for and would never see. Only a
      // genuine PRF gap falls through to the code path.
      if (!(e instanceof PrfUnsupportedError)) throw e;
    }
  }

  const { recoveryCode, request } = await buildEnvelopeV2({
    secret,
    agentSubject,
    driveSubject,
  });

  return { recoveryCode, saved: await saveRecoverySecret(request) };
}

// --- Portal API ---

export async function saveRecoverySecret(input: RecoverySecretInput) {
  const response = await managedFetch(`/recovery-secret`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });

  if (!response.ok) {
    if (response.status === 401) {
      throw new Error(
        `Sign in to ${PRODUCT_NAME} before enabling encrypted recovery.`,
      );
    }

    // Relay what the control plane objected to. It validates the envelope
    // (subject shape, format version, wrapper fields) and says which rule was
    // broken; swallowing that left the one flow where a user can *do*
    // something about it — an identity the server will not accept — showing a
    // sentence that says only "no".
    const reason = await response
      .json()
      .then((body: { error?: string }) => body?.error)
      .catch(() => undefined);

    throw new Error(
      reason
        ? `Could not save encrypted recovery backup: ${reason}.`
        : 'Could not save encrypted recovery backup.',
    );
  }

  const saved = (await response.json()) as RecoverySecret;
  writeManagedAccountBinding(saved.owner_email, saved.agent_subject);
  cacheRecoverySecret(saved);

  return saved;
}

export async function getRecoverySecret(): Promise<RecoverySecret | null> {
  if (!(await getManagedAccount())) return null;
  // [RECOVERY-RECONSTRUCTED] body — only this function's signature survived in
  // the transcripts. Reconstructed as the GET counterpart of saveRecoverySecret
  // (PUT) above; 204/401/404 all mean "no recovery secret stored".
  const response = await managedFetch(`/recovery-secret`, {});

  if (
    response.status === 204 ||
    response.status === 401 ||
    response.status === 404
  ) {
    return null;
  }

  if (!response.ok) {
    throw new Error('Could not load encrypted recovery backup.');
  }

  const fetched = (await response.json()) as RecoverySecret;
  cacheRecoverySecret(fetched);

  return fetched;
}

// --- Local copy of the (encrypted) backup ---

const RECOVERY_CACHE_KEY = 'atomic.recovery.backups';
/** Pre-multi-account single-entry key, folded in on first read. */
const LEGACY_RECOVERY_CACHE_KEY = 'atomic.recovery.backup';

/**
 * Keep this device's own copy of the encrypted backup.
 *
 * It's ciphertext: if it's safe for our servers to hold, it's safe here too —
 * and holding it locally is what lets a signed-out browser be unlocked by a
 * passkey alone, with no email round-trip and no network at all. The DEK is
 * still only reachable through a wrapper (a passkey assertion needs user
 * verification), so a copy on disk grants nobody anything.
 *
 * It does retain `owner_email` after sign-out, which is why "forget this
 * device" exists — see {@link forgetCachedRecoverySecret}.
 */
function cacheRecoverySecret(secret: RecoverySecret): void {
  try {
    // Keyed by agent, so a shared machine accumulates one entry per account
    // rather than each sign-in evicting the last.
    const others = readCachedBackups().filter(
      entry => entry.agent_subject !== secret.agent_subject,
    );
    localStorage.setItem(
      RECOVERY_CACHE_KEY,
      JSON.stringify([...others, secret]),
    );
  } catch {
    // Private mode or quota: unlocking still works while online.
  }
}

/** Every account this device can unlock, most recently saved last. */
export function readCachedBackups(): RecoverySecret[] {
  const entries: RecoverySecret[] = [];

  try {
    const raw = localStorage.getItem(RECOVERY_CACHE_KEY);

    if (raw) entries.push(...(JSON.parse(raw) as RecoverySecret[]));
  } catch {
    // Unreadable or malformed — treated as no cached accounts.
  }

  try {
    // Devices written before multi-account support hold a single entry.
    const legacy = localStorage.getItem(LEGACY_RECOVERY_CACHE_KEY);

    if (legacy) {
      const parsed = JSON.parse(legacy) as RecoverySecret;

      if (!entries.some(e => e.agent_subject === parsed.agent_subject)) {
        entries.push(parsed);
      }

      localStorage.setItem(RECOVERY_CACHE_KEY, JSON.stringify(entries));
      localStorage.removeItem(LEGACY_RECOVERY_CACHE_KEY);
    }
  } catch {
    // Migration is best-effort; the server copy still works.
  }

  return entries;
}

/** The cached backups a passkey on this device could actually open. */
export function readUnlockableCachedBackups(): RecoverySecret[] {
  return readCachedBackups().filter(
    entry => envelopeWrapperKinds(entry).hasPasskey,
  );
}

/**
 * Drop local copies — for a shared machine, or a deliberate clean exit.
 * Without an agent, forgets every account on this device.
 */
export function forgetCachedRecoverySecret(agentSubject?: string): void {
  try {
    if (!agentSubject) {
      localStorage.removeItem(RECOVERY_CACHE_KEY);
      localStorage.removeItem(LEGACY_RECOVERY_CACHE_KEY);

      return;
    }

    const remaining = readCachedBackups().filter(
      entry => entry.agent_subject !== agentSubject,
    );
    localStorage.setItem(RECOVERY_CACHE_KEY, JSON.stringify(remaining));
  } catch {
    // Nothing to do; absence is the desired state either way.
  }
}

/**
 * The backup to unlock with: the server's copy when a session can reach it,
 * otherwise this device's cached copy. The fallback is what makes signing
 * back in on the same machine a single passkey tap.
 *
 * `agentSubject` picks a specific account out of the cache, for a device that
 * holds several; without it the most recently saved one wins.
 */
export async function getUnlockableRecoverySecret(
  agentSubject?: string,
): Promise<RecoverySecret | null> {
  try {
    const fromServer = await getRecoverySecret();

    if (
      fromServer &&
      (!agentSubject || fromServer.agent_subject === agentSubject)
    ) {
      return fromServer;
    }
  } catch {
    // Offline or control plane down — the cache is exactly the fallback.
  }

  const cached = readCachedBackups();

  return (
    (agentSubject
      ? cached.find(entry => entry.agent_subject === agentSubject)
      : cached.at(-1)) ?? null
  );
}
