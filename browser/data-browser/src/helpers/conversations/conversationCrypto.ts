import { AGENT_VAULT_PROOF_MESSAGE } from '@tomic/lib';
import { atomicWasmSource, wasmJsUrl } from '../wasmUrls';
import { agentVaultProof, type VaultProofSigner } from '../managed/vault';

/**
 * End-to-end encryption for conversations, from the wasm bundle.
 *
 * All of the cryptography is `atomic_lib::conversation` (Rust): this file only
 * loads it and passes bytes. The keys it works with are derived from the
 * agent's vault proof, so every device that holds the agent opens the same
 * conversations. See `planning/encrypted-conversations.md`.
 */
type ConversationWasmModule = {
  default: (init?: {
    module_or_path: string | WebAssembly.Module;
  }) => Promise<unknown>;
  conversationEncryptionKey: (vaultProof: Uint8Array) => string;
  conversationAddEpoch: (keyringJson: string, membersJson: string) => string;
  conversationSeal: (
    keyringJson: string,
    agent: string,
    vaultProof: Uint8Array,
    conversation: string,
    plaintext: string,
  ) => string;
  conversationOpen: (
    keyringJson: string,
    agent: string,
    vaultProof: Uint8Array,
    conversation: string,
    sealed: string[],
  ) => (string | null)[];
  conversationSealFile: (
    conversation: string,
    plaintext: Uint8Array,
  ) => { key: string; ciphertext: Uint8Array };
  conversationOpenFile: (
    conversation: string,
    key: string,
    ciphertext: Uint8Array,
  ) => Uint8Array;
};

let modulePromise: Promise<ConversationWasmModule> | null = null;

function loadWasm(): Promise<ConversationWasmModule> {
  if (!modulePromise) {
    modulePromise = (async () => {
      const wasmModule = (await import(
        /* @vite-ignore */ wasmJsUrl()
      )) as ConversationWasmModule;
      await wasmModule.default({ module_or_path: await atomicWasmSource() });

      return wasmModule;
    })().catch(error => {
      // Let the next call retry a failed fetch.
      modulePromise = null;
      throw error;
    });
  }

  return modulePromise;
}

/** Someone a conversation's key is sealed to. */
export interface ConversationMember {
  agent: string;
  encryptionKey: string;
}

/** The signed-in agent, as far as conversations need it. */
export interface ConversationIdentity extends VaultProofSigner {
  subject?: string;
}

/** Proofs are derived once per agent: signing can be slow, and on a
 *  non-deterministic signer it signs twice. */
const proofs = new WeakMap<object, Promise<Uint8Array>>();

function proofFor(agent: ConversationIdentity): Promise<Uint8Array> {
  let proof = proofs.get(agent);

  if (!proof) {
    proof = agentVaultProof(agent, AGENT_VAULT_PROOF_MESSAGE);
    proof.catch(() => proofs.delete(agent));
    proofs.set(agent, proof);
  }

  return proof;
}

function subjectOf(agent: ConversationIdentity): string {
  if (!agent.subject) {
    throw new Error('Sign in to use messages.');
  }

  return agent.subject;
}

/** The public key to publish on the agent as `encryptionKey`. */
export async function encryptionKeyFor(
  agent: ConversationIdentity,
): Promise<string> {
  const [wasm, proof] = await Promise.all([loadWasm(), proofFor(agent)]);

  return wasm.conversationEncryptionKey(proof);
}

/**
 * A keyring with a new epoch whose key only `members` can open. Pass the
 * current keyring on a membership change, or nothing to start one.
 */
export async function addEpoch(
  members: ConversationMember[],
  keyring = '',
): Promise<string> {
  const wasm = await loadWasm();

  return wasm.conversationAddEpoch(keyring, JSON.stringify(members));
}

/** Encrypts `payload` for `conversation` with the newest epoch's key. */
export async function sealPayload(
  agent: ConversationIdentity,
  keyring: string,
  conversation: string,
  payload: SealedPayload,
): Promise<string> {
  const [wasm, proof] = await Promise.all([loadWasm(), proofFor(agent)]);

  return wasm.conversationSeal(
    keyring,
    subjectOf(agent),
    proof,
    conversation,
    JSON.stringify(payload),
  );
}

/**
 * Decrypts sealed messages of one conversation, in order. `null` for one that
 * can't be opened: written before the reader joined, or altered.
 */
export async function openPayloads(
  agent: ConversationIdentity,
  keyring: string,
  conversation: string,
  sealed: string[],
): Promise<(SealedPayload | null)[]> {
  const [wasm, proof] = await Promise.all([loadWasm(), proofFor(agent)]);
  const opened = wasm.conversationOpen(
    keyring,
    subjectOf(agent),
    proof,
    conversation,
    sealed,
  );

  return opened.map(text => (text === null ? null : parsePayload(text)));
}

/** An attachment after encryption on this device. */
export interface SealedFile {
  /** The random key of this file, base64url. It belongs inside the sealed
   *  message that references the file and nowhere else. */
  key: string;
  /** What gets uploaded: version, nonce, ciphertext and tag. */
  ciphertext: Uint8Array;
}

/**
 * Encrypts an attachment for `conversation` under a fresh random key. The key
 * is not derived from the conversation's epoch key, so a later membership
 * change does not matter; the subject is bound in, so the ciphertext cannot be
 * moved to another conversation.
 */
export async function sealFile(
  conversation: string,
  plaintext: Uint8Array,
): Promise<SealedFile> {
  const wasm = await loadWasm();

  return wasm.conversationSealFile(conversation, plaintext);
}

/**
 * Decrypts what {@link sealFile} produced. Throws when the key is wrong, the
 * bytes were altered, or the file was sealed for another conversation.
 */
export async function openFile(
  conversation: string,
  key: string,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const wasm = await loadWasm();

  return wasm.conversationOpenFile(conversation, key, ciphertext);
}

/** What a SealedMessage carries inside `sealed`: what a Message would carry
 *  in the clear. */
export interface SealedPayload {
  text: string;
  replyTo?: string;
}

function parsePayload(text: string): SealedPayload | null {
  try {
    const parsed = JSON.parse(text);

    if (parsed && typeof parsed.text === 'string') {
      return {
        text: parsed.text,
        replyTo:
          typeof parsed.replyTo === 'string' ? parsed.replyTo : undefined,
      };
    }
  } catch {
    // Fall through: a payload we can't parse reads as one we can't open.
  }

  return null;
}
