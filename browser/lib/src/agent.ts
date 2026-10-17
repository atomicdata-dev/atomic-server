import { agentSubject } from './subject.js';
import { Client } from './client.js';
import {
  decodeSecret,
  generateKeyPair,
  JSCryptoProvider,
  legacySubjectFromSecret,
  SubtleCryptoProvider,
  type CryptoProvider,
} from './CryptoProvider.js';
import { decodeB64 } from './base64.js';
import { AtomicError, ErrorType } from './error.js';
import {
  AGENT_VAULT_PROOF_MESSAGE,
  encodeGenesisCert,
  privateDriveCert,
  privateDriveSubject as derivePrivateDriveSubject,
  signBytesWithKey,
  subjectForSignature,
} from './genesis.js';
import { core } from './ontologies/core.js';

export interface StoredAgent {
  subject: string;
  keys: CryptoKeyPair;
}

/**
 * An Agent is a user or machine that can read and/or write data to an Atomic Server. An
 * Agent *might* not have a subject. https://atomicdata.dev/classes/Agent
 */
export class Agent implements AgentInterface {
  public client: Client;
  private _subject?: string;
  public initialDrive?: string;
  /**
   * The `https://server/agents/{pubkey}` subject this identity was issued
   * under, when the secret predates DIDs. Set only for such secrets; see
   * `legacySubjectFromSecret`. The Store uses it to find the Agent resource
   * the old server stored, which holds the name and `drives` the DID has no
   * way of knowing about.
   */
  public legacySubject?: string;
  /**
   * The derived personal-drive DID, computed once from the raw private key at
   * sign-in (see {@link privateDriveSubject} for why it cannot be recomputed
   * from a non-extractable key). Persisted alongside the agent so a restored
   * session still knows which drive is its home.
   */
  public privateDrive?: string;
  /**
   * The agent's Cloud Vault proof: its signature over
   * {@link AGENT_VAULT_PROOF_MESSAGE}, base64url. Same story as
   * {@link privateDrive} — a key that wraps a vault key is derived from this
   * signature, so it has to be the same bytes on every device and every day,
   * and WebKit's WebCrypto produces a different signature each call. Computed
   * once from the raw key at sign-in and carried with the agent.
   */
  public vaultProof?: string;

  #cryptoProvider: CryptoProvider;

  public constructor(
    provider: CryptoProvider,
    subject?: string,
    initialDrive?: string,
  ) {
    if (subject) {
      Client.tryValidSubject(subject);
    }

    this.client = new Client();
    this._subject = subject;
    this.#cryptoProvider = provider;
    this.initialDrive = initialDrive;
  }

  public get subject(): string | undefined {
    return this._subject;
  }

  /**
   * Parses a base64 JSON object containing a privateKey and subject, and
   * constructs an Agent from that.
   */
  public static fromSecret(secretB64: string, type?: 'subtle'): Promise<Agent>;
  public static fromSecret(secretB64: string, type: 'js'): Agent;
  public static fromSecret(
    secretB64: string,
    type: 'js' | 'subtle' = 'subtle',
  ): Agent | Promise<Agent> {
    if (type === 'js') {
      const [provider, subject, initialDrive] =
        JSCryptoProvider.fromSecret(secretB64);
      const agent = new Agent(provider, subject, initialDrive);
      agent.legacySubject = legacySubjectFromSecret(secretB64);

      return agent;
    }

    return new Promise((resolve, reject) => {
      SubtleCryptoProvider.createKeysFromSecret(secretB64)
        .then(async ([keys, subject, initialDrive]) => {
          const provider = new SubtleCryptoProvider(keys);
          const agent = new Agent(provider, subject, initialDrive);
          agent.legacySubject = legacySubjectFromSecret(secretB64);
          // Last moment the raw key is in hand: the keypair above is
          // non-extractable, and this provider cannot reproduce the subject.
          agent.privateDrive =
            await Agent.privateDriveSubjectFromSecret(secretB64);
          agent.vaultProof = await Agent.vaultProofFromSecret(secretB64);

          resolve(agent);
        })
        .catch(() => {
          // Fallback to JS crypto if SubtleCrypto doesn't support Ed25519
          // (e.g. in some headless browser environments)
          try {
            const [provider, subject, initialDrive] =
              JSCryptoProvider.fromSecret(secretB64);
            const fallback = new Agent(provider, subject, initialDrive);
            fallback.legacySubject = legacySubjectFromSecret(secretB64);
            resolve(fallback);
          } catch (e) {
            reject(e);
          }
        });
    });
  }

  public static fromCryptoKeyPair(
    keyPair: CryptoKeyPair,
    subject?: string,
    initialDrive?: string,
  ): Agent {
    const provider = new SubtleCryptoProvider(keyPair);

    return new Agent(provider, subject, initialDrive);
  }

  /**
   * A new agent whose private key exists only in memory and can never be
   * read out: a WebCrypto Ed25519 key generated non-extractable. Its subject
   * is `atomic:agent:<public key>`. For a short-lived signer, such as a
   * plugin frame's key (ontola/atomic-plugins#54), that must not outlive the
   * page or be copied by script.
   *
   * Throws when this environment's WebCrypto has no Ed25519 (older Safari
   * and Android WebViews, ontola/atomic-server#1688) rather than falling back
   * to an extractable JavaScript key, which would defeat the point.
   */
  public static async generateNonExtractable(): Promise<Agent> {
    let keyPair: CryptoKeyPair;

    try {
      keyPair = (await globalThis.crypto.subtle.generateKey(
        { name: 'Ed25519' },
        false,
        ['sign', 'verify'],
      )) as CryptoKeyPair;
    } catch (e) {
      throw new AtomicError(
        `This browser cannot make a non-extractable Ed25519 key (WebCrypto Ed25519 is missing; see atomic-server#1688): ${(e as Error)?.message ?? e}`,
        ErrorType.Client,
      );
    }

    const provider = new SubtleCryptoProvider(keyPair);

    return new Agent(provider, agentSubject(await provider.getPublicKey()));
  }

  /**
   * Generates a new Ed25519 keypair.
   */
  public static async generateKeyPair(): Promise<{
    publicKey: string;
    privateKey: string;
  }> {
    return generateKeyPair();
  }

  /**
   * Builds a secret from a private key and a subject. Give this to a user to store safely or store it in a database.
   */
  public static buildSecret(
    privateKey: string,
    subject: string,
    initialDrive?: string,
  ): string {
    const objJsonStr = JSON.stringify({
      privateKey: privateKey,
      subject: subject,
      initialDrive: initialDrive,
    });

    return btoa(objJsonStr);
  }

  /** Returns public key or generates one using the private key */
  public async getPublicKey(): Promise<string> {
    const publicKey = await this.#cryptoProvider.getPublicKey();

    return publicKey;
  }

  public async sign(message: string): Promise<string> {
    return this.#cryptoProvider.sign(message);
  }

  /** Sign raw bytes (base64url signature). Used to mint a resource's DID from
   * its binary genesis certificate. */
  public async signBytes(data: Uint8Array): Promise<string> {
    return this.#cryptoProvider.signBytes(data);
  }

  /**
   * Deterministic personal-drive DID for this agent. Same key → same subject
   * on every device; no pointer to read.
   *
   * The subject IS an Ed25519 signature over the fixed personal-drive
   * certificate, so this is only stable if the signer is. WebCrypto is not:
   * WKWebView returns a different valid signature every call, which minted a
   * brand-new "My drive" on every lookup (411 of them in one session) because
   * the reuse check in `Store.createDrive` searched for a DID that had never
   * existed.
   *
   * So the value is derived ONCE from the raw private key — with noble's
   * deterministic implementation, matching `ed25519_dalek` on the server — and
   * cached. When neither a cached value nor a deterministic signer is
   * available we throw rather than sign: an unreproducible subject is worse
   * than no subject, because minting under it silently creates junk.
   */
  public async privateDriveSubject(): Promise<string> {
    if (this.privateDrive) {
      return this.privateDrive;
    }

    if (!this.#cryptoProvider.signsDeterministically) {
      throw new AtomicError(
        "Cannot work out this account's private drive: its key signs " +
          'non-deterministically and no derived subject was stored. ' +
          'Sign in with the secret again to recompute it.',
        ErrorType.Client,
      );
    }

    const cert = privateDriveCert(decodeB64(await this.getPublicKey()));
    const subject = subjectForSignature(
      await this.signBytes(encodeGenesisCert(cert)),
    );

    this.privateDrive = subject;

    return subject;
  }

  /**
   * The personal-drive DID implied by a raw private key, independent of which
   * provider ends up holding it. This is the only derivation that works for a
   * SubtleCrypto agent, whose key is non-extractable once stored — hence
   * computing it at sign-in, while the secret is still in hand.
   */
  public static async privateDriveSubjectFromSecret(
    secretB64: string,
  ): Promise<string> {
    const { privateKey } = decodeSecret(secretB64);

    return derivePrivateDriveSubject(new Uint8Array(decodeB64(privateKey)));
  }

  /**
   * The vault proof implied by a raw private key: a deterministic (RFC 8032)
   * signature over {@link AGENT_VAULT_PROOF_MESSAGE}. Like
   * {@link privateDriveSubjectFromSecret}, only possible while the secret is in
   * hand.
   */
  public static async vaultProofFromSecret(secretB64: string): Promise<string> {
    const { privateKey } = decodeSecret(secretB64);

    return signBytesWithKey(
      AGENT_VAULT_PROOF_MESSAGE,
      new Uint8Array(decodeB64(privateKey)),
    );
  }

  /**
   * Whether `signBytes` gives the same signature for the same bytes each time.
   * False for WebCrypto providers (WebKit randomizes Ed25519 nonces); anything
   * that derives a key or identity from a signature must not rely on one.
   */
  public get signsDeterministically(): boolean {
    return this.#cryptoProvider.signsDeterministically;
  }

  public createSignature(subject: string, timestamp: number): Promise<string> {
    const message = `${subject} ${timestamp}`;

    return this.sign(message);
  }

  /**
   * Returns a base64 encoded JSON object containing the Subject and the Private
   * Key. Used for signing in with one string
   */

  /** Fetches the public key for the agent, checks if it matches with the current one */
  public async verifyPublicKeyWithServer(): Promise<void> {
    if (!this.subject) {
      throw new AtomicError(`Agent has no subject`, ErrorType.Client);
    }

    const { resource } = await this.client.fetchResourceHTTP(this.subject);

    if (resource.error) {
      throw new Error(
        `Could not fetch agent, and could therefore not check validity of public key. ${resource.error}`,
      );
    }

    const fetchedPubKey = resource.get(core.properties.publicKey)?.toString();

    if (fetchedPubKey !== (await this.getPublicKey())) {
      throw new Error(
        'Fetched publickey does not match current one - is the private key correct?',
      );
    }
  }
}

/**
 * An Agent is a user or machine that can write data to an Atomic Server. An
 * Agent *might* not have subject, sometimes. https://atomicdata.dev/classes/Agent
 */
export interface AgentInterface {
  /** https://atomicdata.dev/properties/publicKey */
  publicKey?: string;
  /** URL of the Agent */
  subject?: string;
  /** The DID of the drive that should be opened by default for this agent. */
  initialDrive?: string;
}
