import {
  Agent,
  decodeSecret,
  SubtleCryptoProvider,
  JSCryptoProvider,
  legacySubjectFromSecret,
} from '@tomic/react';
import { canonicalIdentifier } from '@tomic/lib';
import { del, get, set } from 'idb-keyval';
import { adoptAgentOnDevice } from './adoptAgent';
import {
  clearSessionDbKeys,
  ensureDbKeyOnSignIn,
  trackDbKeySignIn,
  type SignInCredentials,
} from './localDbKey';

export const AGENT_IDB_KEY = 'atomic.agent';

interface StoredAgent {
  keyPair: CryptoKeyPair;
  subject: string;
  /**
   * Carried across restarts because they only exist on the secret, and the
   * secret is read exactly once — at sign-in. Without them a restored Agent
   * looks brand-new to the pre-DID migration, which reads both and returns at
   * its first line, so a returning user's drives are never adopted. The
   * migration then appears to do nothing forever, having run only in the
   * session where the secret was pasted.
   */
  legacySubject?: string;
  initialDrive?: string;
  /**
   * The derived personal-drive DID. Stored because it cannot be recomputed
   * from the non-extractable keypair beside it: deriving it means signing, and
   * WebCrypto signatures are not reproducible (see
   * `Agent.privateDriveSubject`). Written at sign-in, while the secret is
   * still readable.
   */
  privateDrive?: string;
  /**
   * The agent's Cloud Vault proof (see `Agent.vaultProof`). Stored for the
   * same reason as `privateDrive`: WebKit's WebCrypto signs the fixed proof
   * message differently every call, so the keypair beside it cannot reproduce
   * the signature the vault keys were wrapped under. Readable here, but it is
   * one input of two — the wrapped drive keys live on the control plane, behind
   * the account session — and any script on this origin could already ask the
   * non-extractable key to sign.
   */
  vaultProof?: string;
}

/**
 * A readable private key. Stored *only* where SubtleCrypto is unavailable
 * (an insecure context), never beside a non-extractable keypair.
 */
interface StoredAgentFallback {
  privateKey: string;
  subject: string;
  /** See {@link StoredAgent}. */
  legacySubject?: string;
  initialDrive?: string;
  /** See {@link StoredAgent}. */
  privateDrive?: string;
  /** See {@link StoredAgent}. */
  vaultProof?: string;
}

export const AGENT_FALLBACK_KEY = 'atomic.agent.fallback';

function hasSubtleCrypto(): boolean {
  try {
    return (
      typeof globalThis.crypto?.subtle?.importKey === 'function' &&
      typeof globalThis.crypto?.subtle?.sign === 'function'
    );
  } catch {
    return false;
  }
}

/** What the inline script in index.html read, when it ran (see there). */
interface PrereadAgent {
  agent?: StoredAgent;
  fallback?: StoredAgentFallback;
}

declare global {
  interface Window {
    __atomicAgentRead?: Promise<PrereadAgent | undefined>;
  }
}

/**
 * Take the IndexedDB read that index.html started before the app's JavaScript
 * had loaded. Consumed once: a later call (after a sign-in or sign-out) must
 * read the database again. Undefined when the script did not run or its read
 * failed, and the caller then reads as it always did.
 */
async function takePreread(): Promise<PrereadAgent | undefined> {
  if (typeof window === 'undefined') return undefined;

  const pending = window.__atomicAgentRead;
  window.__atomicAgentRead = undefined;

  try {
    return await pending;
  } catch {
    return undefined;
  }
}

export async function getAgentFromIDB(): Promise<Agent | undefined> {
  const preread = await takePreread();
  const readAgent = async () =>
    (preread ? preread.agent : await get(AGENT_IDB_KEY)) as
      | StoredAgent
      | undefined;
  const readFallback = async () =>
    (preread ? preread.fallback : await get(AGENT_FALLBACK_KEY)) as
      | StoredAgentFallback
      | undefined;

  // Try SubtleCrypto first (secure context)
  if (hasSubtleCrypto()) {
    const storedAgent = await readAgent();

    if (storedAgent) {
      try {
        const provider = new SubtleCryptoProvider(storedAgent.keyPair);
        // Prove the stored keypair can actually sign before dropping any
        // readable copy below — a corrupt keypair must not lock the user out.
        await provider.sign('atomic-key-check');

        const agent = new Agent(
          provider,
          storedAgent.subject,
          storedAgent.initialDrive,
        );
        agent.legacySubject = storedAgent.legacySubject;
        agent.privateDrive = storedAgent.privateDrive;
        agent.vaultProof = storedAgent.vaultProof;

        // Heal installs written while the readable key was saved
        // unconditionally: a plaintext copy beside a non-extractable key hands
        // back exactly what non-extractability is meant to withhold.
        await del(AGENT_FALLBACK_KEY);

        return agent;
      } catch (e) {
        console.warn(
          'Failed to load agent with SubtleCrypto, trying fallback:',
          e,
        );
      }
    }
  }

  // Fallback: load from plaintext private key (insecure context)
  const fallback = await readFallback();

  if (fallback) {
    try {
      const agent = new Agent(
        new JSCryptoProvider(fallback.privateKey),
        fallback.subject,
        fallback.initialDrive,
      );
      agent.legacySubject = fallback.legacySubject;
      agent.privateDrive = fallback.privateDrive;
      agent.vaultProof = fallback.vaultProof;

      return agent;
    } catch (e) {
      console.error('Failed to load agent from fallback:', e);
    }
  }

  return undefined;
}

export interface SaveAgentOptions {
  /**
   * Also make this device's embedded node act as this agent (see
   * `helpers/adoptAgent.ts`). Default true — signing in *is* the moment the
   * device takes on an identity. Pass false for throwaway agents (the demo
   * guest) that must not become the node's identity.
   */
  adoptOnDevice?: boolean;
}

export async function saveAgentToIDB(
  keyPair: CryptoKeyPair,
  subject: string,
): Promise<void>;
export async function saveAgentToIDB(
  secret: string | undefined,
  options?: SaveAgentOptions,
): Promise<void>;
export async function saveAgentToIDB(
  keyPairOrSecret: CryptoKeyPair | string | undefined,
  subjectOrOptions?: string | SaveAgentOptions,
): Promise<void> {
  const subject =
    typeof subjectOrOptions === 'string' ? subjectOrOptions : undefined;
  const options =
    typeof subjectOrOptions === 'object' ? subjectOrOptions : undefined;

  if (keyPairOrSecret === undefined) {
    await del(AGENT_IDB_KEY);
    await del(AGENT_FALLBACK_KEY);
    // Sign-out: drop the session copies of the local-database encryption
    // keys. The wrapped copies survive, so the encrypted OPFS caches become
    // readable again on the owning agent's next sign-in — while this
    // signed-out session can no longer open them.
    await clearSessionDbKeys();

    return;
  }

  if (typeof keyPairOrSecret === 'string') {
    const stored = storeSecret(keyPairOrSecret);
    // Announced before anything is awaited: callers often set the agent first,
    // and the database opener that event starts must know a sign-in is about
    // to deliver this agent's key (see `waitForSessionDbKey`).
    const signingIn = subjectOfSecret(keyPairOrSecret);

    if (signingIn) trackDbKeySignIn(signingIn, stored);

    await stored;

    // The device now holds this agent; its node should sign as this agent too.
    // Best-effort and last, so a node that isn't up yet can't block sign-in.
    if (options?.adoptOnDevice !== false) {
      await adoptAgentOnDevice(keyPairOrSecret);
    }

    return;
  }

  if (!subject) {
    throw new Error('Subject is required');
  }

  // Preserve the secret-only fields: this overload re-stores a keypair and
  // has no secret to re-derive them from, and dropping them would silently
  // disable the migration for a returning user.
  const previous = (await get(AGENT_IDB_KEY)) as StoredAgent | undefined;

  await set(AGENT_IDB_KEY, {
    keyPair: keyPairOrSecret,
    subject,
    legacySubject:
      previous?.subject === subject ? previous.legacySubject : undefined,
    initialDrive:
      previous?.subject === subject ? previous.initialDrive : undefined,
    privateDrive:
      previous?.subject === subject ? previous.privateDrive : undefined,
    vaultProof: previous?.subject === subject ? previous.vaultProof : undefined,
  } satisfies StoredAgent);
}

/**
 * The agent subject a secret signs in as (the same one `storeSecret` stores),
 * or undefined when the secret cannot be read.
 */
function subjectOfSecret(secret: string): string | undefined {
  try {
    return decodeSecret(secret).subject;
  } catch {
    return undefined;
  }
}

/** Persist the agent's key, preferring a non-extractable keypair. */
async function storeSecret(secret: string): Promise<void> {
  // The secret is a base64-encoded JSON containing { privateKey, subject }.
  // The raw private key is needed below for the JS fallback record, and to
  // derive the wrapping key for the local-database encryption key — this is
  // the only moment it passes through JS once the keypair is stored
  // non-extractably.
  const decoded = JSON.parse(atob(secret));
  // Derived here, once, from the raw key — the stored keypair cannot
  // reproduce it. See `StoredAgent.privateDrive`.
  const privateDrive = await Agent.privateDriveSubjectFromSecret(secret);
  const vaultProof = await Agent.vaultProofFromSecret(secret);

  {
    // Prefer the non-extractable keypair. Once stored this way the private key
    // cannot be read back out of IndexedDB by anything running on this origin,
    // so no readable copy may be left beside it.
    if (hasSubtleCrypto()) {
      try {
        const [keyPair, resolvedSubject] =
          await SubtleCryptoProvider.createKeysFromSecret(secret);
        await set(AGENT_IDB_KEY, {
          keyPair,
          subject: resolvedSubject,
          legacySubject: legacySubjectFromSecret(secret),
          initialDrive: decoded.initialDrive,
          privateDrive,
          vaultProof,
        } satisfies StoredAgent);
        await del(AGENT_FALLBACK_KEY);

        await ensureLocalDbKey(resolvedSubject, {
          privateKey: decoded.privateKey,
          vaultProof,
        });

        return;
      } catch {
        // SubtleCrypto refused the key — fall through to the readable record.
      }
    }

    // Insecure context (plain-HTTP self-hosted origin): Web Crypto is absent,
    // so a readable key is the only way to sign at all. The secret is no more
    // exposed than the unencrypted connection already carrying it.
    const [, newSubject] = JSCryptoProvider.fromSecret(secret);
    await set(AGENT_FALLBACK_KEY, {
      privateKey: decoded.privateKey,
      subject: newSubject,
      legacySubject: legacySubjectFromSecret(secret),
      initialDrive: decoded.initialDrive,
      privateDrive,
      vaultProof,
    } satisfies StoredAgentFallback);
    // Drop a keypair from a previous account, so it can't be loaded instead.
    await del(AGENT_IDB_KEY);

    await ensureLocalDbKey(newSubject, {
      privateKey: decoded.privateKey,
      vaultProof,
    });
  }
}

/**
 * Set up this agent's local-database encryption key (unwrap the durable copy,
 * or create one). Best-effort: a failure here degrades to a fresh cache key,
 * never blocks sign-in.
 */
async function ensureLocalDbKey(
  subject: string,
  credentials: SignInCredentials,
): Promise<void> {
  try {
    await ensureDbKeyOnSignIn(subject, credentials);
  } catch (e) {
    console.warn('Failed to prepare local database key:', e);
  }
}

const PREVIOUS_IDENTITIES_KEY = 'atomic.previousIdentities';

/**
 * An identity this device used to be, kept when the account's identity
 * replaced it. In IndexedDB rather than localStorage: a non-extractable
 * keypair survives structured clone but has no string form, and in a secure
 * context that keypair is all there is — the secret itself is gone.
 */
export interface PreviousIdentity {
  subject: string;
  savedAt: number;
  /** The stored record as it was, keypair (or readable key) included. */
  record: StoredAgent | StoredAgentFallback;
  /** Only where the key was readable (insecure context). */
  secret?: string;
  /**
   * Local-only drives. They live in this identity's own encrypted database,
   * so they are reachable only by signing in as it again.
   */
  localOnlyDrives: string[];
}

export async function readPreviousIdentities(): Promise<PreviousIdentity[]> {
  const list = (await get(PREVIOUS_IDENTITIES_KEY)) as
    | PreviousIdentity[]
    | undefined;

  return Array.isArray(list) ? list : [];
}

/**
 * Copy the stored agent `subject` aside before another identity overwrites
 * it, so switching never locks anything away. Idempotent: archiving the same
 * identity again only adds drives it did not list yet.
 *
 * Throws when the device holds no key for `subject`: switching would then
 * lose the identity for good, which the caller must not do silently.
 */
export async function archiveStoredAgent(
  subject: string,
  localOnlyDrives: string[] = [],
): Promise<void> {
  const list = await readPreviousIdentities();
  // The same agent is spelled `atomic:agent:` in backups and secrets from
  // before the rename and `did:ad:agent:` once stored, so compare identities,
  // not strings: a strict match made the reconcile gate's handover fail with
  // "no stored key" for a key this device does hold.
  const isSubject = (candidate: string | undefined) =>
    candidate !== undefined &&
    canonicalIdentifier(candidate) === canonicalIdentifier(subject);
  const existing = list.find(entry => isSubject(entry.subject));

  if (existing) {
    existing.localOnlyDrives = [
      ...new Set([...existing.localOnlyDrives, ...localOnlyDrives]),
    ];
    await set(PREVIOUS_IDENTITIES_KEY, list);

    return;
  }

  const stored = (await get(AGENT_IDB_KEY)) as StoredAgent | undefined;
  const fallback = (await get(AGENT_FALLBACK_KEY)) as
    | StoredAgentFallback
    | undefined;
  const record = isSubject(stored?.subject)
    ? stored
    : isSubject(fallback?.subject)
      ? fallback
      : undefined;

  if (!record) {
    throw new Error(`no stored key for ${subject}`);
  }

  // Keep what the device holds, in its own spelling, whichever one was asked for.
  list.push({
    subject: record.subject,
    savedAt: Date.now(),
    record,
    secret:
      'privateKey' in record
        ? Agent.buildSecret(
            record.privateKey,
            record.subject,
            record.initialDrive,
          )
        : undefined,
    localOnlyDrives: [...new Set(localOnlyDrives)],
  });
  await set(PREVIOUS_IDENTITIES_KEY, list);
}
