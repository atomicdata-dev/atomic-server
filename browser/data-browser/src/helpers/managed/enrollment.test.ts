import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Agent, JSCryptoProvider, decodeB64 } from '@tomic/lib';

const managedFetch = vi.fn();
vi.mock('./api', () => ({
  managedFetch: (...a: unknown[]) => managedFetch(...a),
  getManagedApiBase: () => 'https://portal.example/api',
}));
vi.mock('./session', () => ({ getManagedAccount: async () => null }));
vi.mock('./binding', () => ({ writeManagedAccountBinding: () => undefined }));

const { createManagedSyncEnrollment, buildEnrollmentProof, genesisCertOf } =
  await import('./enrollment');

beforeEach(() => {
  managedFetch.mockReset();
});

const failWith = (status: number, body: unknown) =>
  managedFetch.mockResolvedValue({
    ok: false,
    status,
    json: async () => body,
  });

const succeedWith = (body: unknown) => ({
  ok: true,
  status: 200,
  json: async () => body,
});

const enroll = () =>
  createManagedSyncEnrollment({
    driveSubject: 'did:ad:drive',
    agentSubject: 'did:ad:agent:x',
  });

const failureOf = async (promise: Promise<unknown>): Promise<Error> => {
  try {
    await promise;
  } catch (e) {
    return e as Error;
  }

  throw new Error('expected the enrollment to fail');
};

/**
 * Every one of these used to raise the same sentence, which is how a full
 * fleet in production read as a mysterious backup failure with no next step.
 */
describe('createManagedSyncEnrollment failures', () => {
  it('returns a typed payment requirement for the hosting handoff', async () => {
    failWith(402, {
      error: 'Cloud Server requires a subscription',
      upgrade_url: 'https://portal.example/billing',
    });

    await expect(enroll()).rejects.toMatchObject({
      name: 'HostingPaymentRequiredError',
    });
  });

  /** Actionable, and distinct from "we are broken". */
  it('says the session lapsed on a 401', async () => {
    failWith(401, { error: 'No session' });
    await expect(enroll()).rejects.toThrow(/session expired/i);
  });

  /**
   * A 500 here is nearly always no node with free capacity, and the body says
   * only "Internal Server Error" — so the message must not simply repeat it.
   */
  it('explains a 500 as capacity rather than parroting the body', async () => {
    failWith(500, { error: 'Internal Server Error' });

    const error = await failureOf(enroll());
    expect(error.message).toMatch(/capacity/i);
    expect(error.message).not.toMatch(/Internal Server Error/);
  });

  /** A body-less failure still has to name something. */
  it('falls back to the status when there is no body', async () => {
    managedFetch.mockResolvedValue({
      ok: false,
      status: 418,
      json: async () => {
        throw new Error('not json');
      },
    });

    await expect(enroll()).rejects.toThrow(/418/);
  });

  /**
   * The control plane's 403s name the reason in `error_code`; the user gets a
   * sentence about what to do, not the server's talk of signatures.
   */
  it('turns a refused proof into a user-facing explanation', async () => {
    failWith(403, {
      error: 'enrollment proof: signature does not verify',
      error_code: 'enrollment_proof_invalid',
    });

    const error = await failureOf(enroll());
    expect(error.message).toMatch(/could not verify.*controls the workspace/i);
    expect(error.message).not.toMatch(/signature does not verify/);
  });

  it('explains a missing proof as something to retry after signing in', async () => {
    failWith(403, {
      error: 'enrollment proof required',
      error_code: 'enrollment_proof_required',
    });

    await expect(enroll()).rejects.toThrow(/no proof was sent/i);
  });
});

// A fixed Ed25519 key, so the derived personal-drive DID is stable.
const PRIVATE_KEY = 'CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=';

async function testAgent(): Promise<Agent> {
  const provider = new JSCryptoProvider(PRIVATE_KEY);
  const publicKey = await provider.getPublicKey();

  return new Agent(provider, `did:ad:agent:${publicKey}`);
}

/** A fresh `ArrayBuffer`-backed copy, which is what WebCrypto's types accept. */
const bytes = (b64: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(decodeB64(b64));

/** Verify an Ed25519 signature with WebCrypto — independent of `@tomic/lib`'s signer. */
async function verifies(
  publicKeyB64: string,
  message: string,
  signatureB64: string,
): Promise<boolean> {
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    bytes(publicKeyB64),
    { name: 'Ed25519' },
    false,
    ['verify'],
  );

  return globalThis.crypto.subtle.verify(
    { name: 'Ed25519' },
    key,
    bytes(signatureB64),
    new TextEncoder().encode(message),
  );
}

const challengeFor = (agentSubject: string, driveSubject: string) => ({
  nonce: 'nonce-1',
  challenge: `atomic-saas:enroll:v1:nonce-1:${driveSubject}:me@example.com:1900000000`,
  drive_subject: driveSubject,
  agent_subject: agentSubject,
  expires_at: 1900000000,
});

describe('buildEnrollmentProof', () => {
  it('signs "{challenge} {timestamp}" with the agent key and echoes the nonce', async () => {
    const agent = await testAgent();
    const challenge = challengeFor(agent.subject!, 'did:ad:somedrive');

    const proof = await buildEnrollmentProof({
      challenge,
      agent,
      driveSubject: 'did:ad:somedrive',
      genesisCert: 'AQID',
    });

    expect(proof.nonce).toBe('nonce-1');
    expect(proof.public_key).toBe(await agent.getPublicKey());
    expect(typeof proof.timestamp).toBe('number');
    expect(
      await verifies(
        proof.public_key,
        `${challenge.challenge} ${proof.timestamp}`,
        proof.signature,
      ),
    ).toBe(true);
    // Not a signature over the bare challenge: the timestamp is bound in.
    expect(
      await verifies(proof.public_key, challenge.challenge, proof.signature),
    ).toBe(false);
  });

  it('attaches the genesis certificate for a drive that is not the personal one', async () => {
    const agent = await testAgent();

    const proof = await buildEnrollmentProof({
      challenge: challengeFor(agent.subject!, 'did:ad:shared'),
      agent,
      driveSubject: 'did:ad:shared',
      genesisCert: 'AQID',
    });

    expect(proof.genesis_cert).toBe('AQID');
  });

  it('leaves the certificate off for the personal drive', async () => {
    const agent = await testAgent();
    const personal = await agent.privateDriveSubject();

    const proof = await buildEnrollmentProof({
      challenge: challengeFor(agent.subject!, personal),
      agent,
      driveSubject: personal,
      // The personal drive carries one too; the control plane derives it.
      genesisCert: 'AQID',
    });

    expect(proof).not.toHaveProperty('genesis_cert');
  });

  it('refuses to sign a challenge issued for another agent', async () => {
    const agent = await testAgent();

    await expect(
      buildEnrollmentProof({
        challenge: challengeFor('did:ad:agent:someoneelse', 'did:ad:d'),
        agent,
        driveSubject: 'did:ad:d',
      }),
    ).rejects.toThrow(/someoneelse/);
  });

  it('reads the certificate off the drive resource', () => {
    expect(
      genesisCertOf({
        get: p =>
          p === 'https://atomicdata.dev/properties/genesis'
            ? 'AQID'
            : undefined,
      }),
    ).toBe('AQID');
    expect(genesisCertOf({ get: () => '' })).toBeUndefined();
  });
});

describe('createManagedSyncEnrollment with an agent', () => {
  const bodyOf = (call: unknown[]) =>
    JSON.parse((call[1] as { body: string }).body) as Record<string, unknown>;

  const created = { drive: 'did:ad:shared', node: null, http_origin: null };

  it('requests a challenge, signs it, and sends the proof', async () => {
    const agent = await testAgent();
    const challenge = challengeFor(agent.subject!, 'did:ad:shared');

    managedFetch
      .mockResolvedValueOnce(succeedWith(challenge))
      .mockResolvedValueOnce(succeedWith(created));

    await createManagedSyncEnrollment({
      driveSubject: 'did:ad:shared',
      agentSubject: agent.subject!,
      agent,
      genesisCert: 'AQID',
      hostingConsentVersion: 1,
    });

    expect(managedFetch).toHaveBeenCalledTimes(2);
    expect(managedFetch.mock.calls[0][0]).toBe('/sync-enrollments/challenge');
    expect(bodyOf(managedFetch.mock.calls[0])).toEqual({
      drive_subject: 'did:ad:shared',
      agent_subject: agent.subject,
    });

    expect(managedFetch.mock.calls[1][0]).toBe('/sync-enrollments');
    const body = bodyOf(managedFetch.mock.calls[1]);
    expect(body.hosting_consent_version).toBe(1);
    const proof = body.proof as Record<string, unknown>;
    expect(proof.nonce).toBe('nonce-1');
    expect(proof.genesis_cert).toBe('AQID');
    expect(proof.public_key).toBe(await agent.getPublicKey());
    expect(
      await verifies(
        proof.public_key as string,
        `${challenge.challenge} ${proof.timestamp}`,
        proof.signature as string,
      ),
    ).toBe(true);
  });

  /**
   * An older control plane has no challenge route. The app must keep working
   * against it — unsigned, exactly as before — rather than fail every backup
   * until the fleet is upgraded.
   */
  it('falls back to an unsigned enrollment when the challenge route 404s', async () => {
    const agent = await testAgent();

    managedFetch
      .mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({ error: 'Not Found' }),
      })
      .mockResolvedValueOnce(succeedWith(created));

    const result = await createManagedSyncEnrollment({
      driveSubject: 'did:ad:shared',
      agentSubject: agent.subject!,
      agent,
      genesisCert: 'AQID',
    });

    expect(result.drive).toBe('did:ad:shared');
    expect(managedFetch).toHaveBeenCalledTimes(2);
    expect(bodyOf(managedFetch.mock.calls[1])).toEqual({
      drive_subject: 'did:ad:shared',
      agent_subject: agent.subject,
    });
  });

  /** Any other challenge failure is a real failure, surfaced like the rest. */
  it('surfaces a challenge failure other than 404', async () => {
    const agent = await testAgent();

    failWith(401, { error: 'No session' });

    await expect(
      createManagedSyncEnrollment({
        driveSubject: 'did:ad:shared',
        agentSubject: agent.subject!,
        agent,
      }),
    ).rejects.toThrow(/session expired/i);
    expect(managedFetch).toHaveBeenCalledTimes(1);
  });

  it('never asks for a challenge without an agent to sign it', async () => {
    managedFetch.mockResolvedValue(succeedWith(created));

    await enroll();

    expect(managedFetch).toHaveBeenCalledTimes(1);
    expect(managedFetch.mock.calls[0][0]).toBe('/sync-enrollments');
    expect(bodyOf(managedFetch.mock.calls[0])).not.toHaveProperty('proof');
  });
});
