import { type Agent, createAuthentication, GENESIS } from '@tomic/lib';
import { PRODUCT_NAME } from './product';
import { managedFetch } from './api';
import { writeManagedAccountBinding } from './binding';
import { getManagedAccount } from './session';

/**
 * What the control plane returns from `POST /api/sync-enrollments`
 * (`SyncEnrollmentCreated` in the backend). `http_origin` is the managed node
 * the drive was assigned to — where the browser then points to sync it.
 */
export type ManagedSyncEnrollmentResult = {
  drive: string;
  /** Iroh node id of the assigned node, when known. */
  node: string | null;
  /** HTTP origin of the assigned managed node, e.g. `https://node1.example`. */
  http_origin: string | null;
};

/**
 * What `POST /api/sync-enrollments/challenge` hands back. The control plane
 * stores every bound field itself; the client only echoes `nonce` and signs
 * `challenge`.
 */
export type ManagedEnrollmentChallenge = {
  nonce: string;
  challenge: string;
  drive_subject: string;
  agent_subject: string;
  expires_at: number;
};

/**
 * The signed answer to a {@link ManagedEnrollmentChallenge} — the `proof`
 * field of `POST /api/sync-enrollments` (`EnrollmentProof` in the control
 * plane's `enrollment_proof.rs`).
 */
export type ManagedEnrollmentProof = {
  nonce: string;
  public_key: string;
  timestamp: number;
  signature: string;
  /** Base64 genesis certificate of the drive; omitted for a personal drive,
   *  whose certificate the control plane derives from the agent's key. */
  genesis_cert?: string;
};

/** Why an enrollment was refused, when the control plane names the reason. */
export type ManagedEnrollmentErrorCode =
  | 'enrollment_proof_required'
  | 'enrollment_proof_invalid'
  | (string & {});

const PROOF_ERROR_MESSAGES: Record<string, string> = {
  enrollment_proof_required:
    `${PRODUCT_NAME} needs proof that this device controls the workspace ` +
    'before hosting it, but no proof was sent. Sign in again and retry.',
  enrollment_proof_invalid:
    `${PRODUCT_NAME} could not verify that this device controls the ` +
    'workspace: only the identity that created it can back it up. If this is ' +
    'your workspace, sign in with the identity that created it and retry.',
};

/**
 * Say what actually went wrong.
 *
 * This used to throw one sentence — "Could not enable Cloud Server" — for every
 * failure, discarding the status and the body. The control plane is more
 * forthcoming than that: it answers 402 with "Cloud Server requires a
 * subscription" and an upgrade URL, 401 when the session lapsed, 403 with an
 * `error_code` when the enrollment proof is missing or does not check out,
 * and 500 when the fleet has no node with free capacity. All of these arrived
 * as the same dead end, which is how a full fleet in production read as a
 * mysterious backup failure with no next step.
 */
async function enrollmentError(response: Response): Promise<Error> {
  const body = (await response.json().catch(() => null)) as {
    error?: string;
    error_code?: ManagedEnrollmentErrorCode;
    upgrade_url?: string;
  } | null;

  if (response.status === 401) {
    return new Error(
      `Your ${PRODUCT_NAME} session expired. Sign in and retry.`,
    );
  }

  // A refused proof gets a sentence that says what the user can do about it;
  // the server's own wording is about signatures and certificates.
  const proofMessage =
    body?.error_code && PROOF_ERROR_MESSAGES[body.error_code];

  if (proofMessage) {
    return new Error(proofMessage);
  }

  // The server's own words when it has them: it knows why far better than a
  // status code does.
  if (body?.error && response.status !== 500) {
    return new Error(
      body.upgrade_url ? `${body.error} (${body.upgrade_url})` : body.error,
    );
  }

  if (response.status >= 500) {
    return new Error(
      `${PRODUCT_NAME} could not place this drive right now. This is usually ` +
        'capacity rather than anything you did — try again shortly.',
    );
  }

  return new Error(
    `Could not enable ${PRODUCT_NAME} hosting (HTTP ${response.status}).`,
  );
}

/**
 * Ask the control plane for an enrollment challenge to sign.
 *
 * Returns `null` when the control plane has no challenge route (404): an older
 * deployment that still trusts the session plus the client-supplied DIDs. The
 * caller then enrolls unsigned, exactly as before the proof existed, so a
 * newer app keeps working against an older control plane.
 */
export async function requestEnrollmentChallenge({
  driveSubject,
  agentSubject,
}: {
  driveSubject: string;
  agentSubject: string;
}): Promise<ManagedEnrollmentChallenge | null> {
  const response = await managedFetch(`/sync-enrollments/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      drive_subject: driveSubject,
      agent_subject: agentSubject,
    }),
  });

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    throw await enrollmentError(response);
  }

  return (await response.json()) as ManagedEnrollmentChallenge;
}

/**
 * Whether `driveSubject` is `agent`'s personal drive — the DID derived from
 * its key alone. If that derivation is unavailable (a non-deterministic
 * SubtleCrypto signer with no stored subject), treat the drive as
 * non-personal: sending the certificate for a personal drive is merely
 * redundant, while omitting it for a non-personal one fails the proof.
 */
async function isPersonalDrive(
  agent: Agent,
  driveSubject: string,
): Promise<boolean> {
  try {
    return (await agent.privateDriveSubject()) === driveSubject;
  } catch {
    return false;
  }
}

/**
 * Answer a challenge with the agent's signature, in the shape the control
 * plane's `EnrollmentProof` expects.
 *
 * Signing reuses `@tomic/lib`'s `createAuthentication`: the challenge is
 * signed exactly as a request subject would be (`"{challenge} {timestamp}"`),
 * with the same key and encoding, so nothing cryptographic is reimplemented
 * here. The `atomic-saas:enroll:` prefix of a challenge can never collide with
 * a URL, so a proof cannot double as request authentication.
 *
 * `genesisCert` is the drive's `genesis` propval (base64). It is attached only
 * when the drive is not the agent's personal drive: the control plane rebuilds
 * a personal drive's certificate from the public key, but for any other drive
 * it needs the certificate to check that this agent created it.
 */
export async function buildEnrollmentProof({
  challenge,
  agent,
  driveSubject,
  genesisCert,
}: {
  challenge: ManagedEnrollmentChallenge;
  agent: Agent;
  driveSubject: string;
  genesisCert?: string;
}): Promise<ManagedEnrollmentProof> {
  if (agent.subject !== challenge.agent_subject) {
    throw new Error(
      `${PRODUCT_NAME} issued the challenge for ${challenge.agent_subject}, ` +
        `but the signing identity is ${agent.subject}.`,
    );
  }

  const auth = await createAuthentication(challenge.challenge, agent);
  const personal = await isPersonalDrive(agent, driveSubject);

  return {
    nonce: challenge.nonce,
    public_key: auth['https://atomicdata.dev/properties/auth/publicKey'],
    timestamp: auth['https://atomicdata.dev/properties/auth/timestamp'],
    signature: auth['https://atomicdata.dev/properties/auth/signature'],
    ...(personal || !genesisCert ? {} : { genesis_cert: genesisCert }),
  };
}

/** The drive's inline genesis certificate, base64, if the resource carries one. */
export function genesisCertOf(drive: {
  get: (property: string) => unknown;
}): string | undefined {
  const value = drive.get(GENESIS);

  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * Enroll a drive for hosting on the control plane.
 *
 * With an `agent`, the request carries a signed proof of control: a challenge
 * is requested, signed with the agent's key, and sent along (see
 * {@link buildEnrollmentProof}). Without one — or against a control plane that
 * does not issue challenges — the request is unsigned, which an older or
 * lenient control plane still accepts.
 */
export async function createManagedSyncEnrollment({
  driveSubject,
  agentSubject,
  agent,
  genesisCert,
  hostingConsentVersion,
}: {
  driveSubject: string;
  agentSubject: string;
  /** The agent holding the key for `agentSubject`; signs the challenge. */
  agent?: Agent;
  /** The drive's `genesis` propval, for a drive that is not the agent's personal drive. */
  genesisCert?: string;
  hostingConsentVersion?: number;
}): Promise<ManagedSyncEnrollmentResult> {
  // Identity convergence happens silently at app boot (IdentityReconcileGate);
  // by the time we enroll, the active agent is the account's agent. Enrolling
  // also (re)binds it below, so the account adopts the agent in use here — we
  // never block enrollment with a mismatch error.
  const challenge = agent
    ? await requestEnrollmentChallenge({ driveSubject, agentSubject })
    : null;

  const proof =
    agent && challenge
      ? await buildEnrollmentProof({
          challenge,
          agent,
          driveSubject,
          genesisCert,
        })
      : undefined;

  const response = await managedFetch(`/sync-enrollments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      drive_subject: driveSubject,
      agent_subject: agentSubject,
      hosting_consent_version: hostingConsentVersion,
      ...(proof ? { proof } : {}),
    }),
  });

  if (!response.ok) {
    throw await enrollmentError(response);
  }

  const managedAccount = await getManagedAccount().catch(() => null);

  if (managedAccount) {
    writeManagedAccountBinding(managedAccount.email, agentSubject);
  }

  return (await response.json()) as ManagedSyncEnrollmentResult;
}
