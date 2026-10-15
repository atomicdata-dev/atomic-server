import { describe, it } from 'vitest';
import { Agent } from './agent.js';
import { decodeB64 } from './base64.js';
import { JSCryptoProvider, legacySubjectFromSecret } from './CryptoProvider.js';
import { AGENT_VAULT_PROOF_MESSAGE, privateDriveSubject } from './genesis.js';
import { isAgentSubject, isAtomicIdentifier } from './subject.js';

describe('Agent', () => {
  const validPrivateKey = 'CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=';
  const validSubject =
    'https://atomicdata.dev/agents/PLwTOXVvQdHYpaLEq5IozLNeUBdXMVchKjFwFfamBlo=';

  it('Constructs valid ', async ({ expect }) => {
    const validAgent = () =>
      new Agent(new JSCryptoProvider(validPrivateKey), validSubject);
    expect(validAgent).not.to.throw();
    // Can't get this to throw yet
    // const invalidAgentSignature = () => new Agent(validSubject, 'ugh');
    // expect(invalidAgentSignature).to.throw();
    const invalidAgentUrl = () =>
      new Agent(new JSCryptoProvider(validPrivateKey), 'not a url');
    expect(invalidAgentUrl).to.throw();
  });

  it('signs any string correctly', async ({ expect }) => {
    const agent = new Agent(
      new JSCryptoProvider(validPrivateKey),
      validSubject,
    );
    const input = 'val';
    // base64url (RFC 4648 §5, unpadded) — matches the Rust signer encoding.
    const correct_signature_rust =
      'YtDR_xo0272LHNBQtDer4LekzdkfUANFTI0eHxZhITXnbC3j0LCqDWhr6itNvo4tFnep6DCbev5OKAHH89-TDA';
    const signature = await agent.sign(input);
    expect(signature).to.equal(correct_signature_rust);
  });

  it('creates the right public key', async ({ expect }) => {
    const agent = new Agent(
      new JSCryptoProvider(validPrivateKey),
      validSubject,
    );
    const generatedPublickey = await agent.getPublicKey();
    expect(generatedPublickey).to.equal(
      '7LsjMW5gOfDdJzK_atgjQ1t20J_rw8MjVg6xwqm-h8U',
    );
  });

  it('derives a stable personal-drive DID from the key', async ({ expect }) => {
    const agent = new Agent(
      new JSCryptoProvider(validPrivateKey),
      validSubject,
    );
    const first = await agent.privateDriveSubject();
    const second = await agent.privateDriveSubject();
    expect(first).toBe(second);
    expect(first).toBe(await privateDriveSubject(decodeB64(validPrivateKey)));
    expect(isAtomicIdentifier(first)).toBe(true);
    expect(isAgentSubject(first)).toBe(false);
  });

  /**
   * The vault proof is key material: `agent_secret_kek` on the server derives
   * the key that wraps a drive's vault key from it. So it must be the RFC 8032
   * deterministic signature — the one a `js` agent produces — regardless of
   * which provider the agent ends up with, and it must survive re-derivation.
   */
  it('derives the vault proof deterministically from the secret', async ({
    expect,
  }) => {
    const secret = Agent.buildSecret(validPrivateKey, validSubject);
    const jsAgent = Agent.fromSecret(secret, 'js');

    const fromSecret = await Agent.vaultProofFromSecret(secret);
    expect(fromSecret).toBe(await Agent.vaultProofFromSecret(secret));
    expect(fromSecret).toBe(await jsAgent.signBytes(AGENT_VAULT_PROOF_MESSAGE));
    expect(decodeB64(fromSecret)).toHaveLength(64);
  });
});

describe('legacySubjectFromSecret', () => {
  const b64 = (o: unknown) => btoa(JSON.stringify(o));

  it('recovers the pre-DID subject, which only the secret still knows', ({
    expect,
  }) => {
    const pk = 'QmfpRIBn2JYEatT0MjSkMNoBJzstz19orwnT5oT2rcQ=';
    expect(
      legacySubjectFromSecret(
        b64({
          privateKey: 'x',
          subject: `https://atomicdata.dev/agents/${pk}`,
        }),
      ),
    ).toBe(`https://atomicdata.dev/agents/${pk}`);
    // http and a port, as a self-hosted pre-DID server would have issued.
    expect(
      legacySubjectFromSecret(
        b64({ privateKey: 'x', subject: `http://localhost:9883/agents/${pk}` }),
      ),
    ).toBe(`http://localhost:9883/agents/${pk}`);
  });

  it('returns undefined for a modern secret', ({ expect }) => {
    // The DID is derivable from the key, so there is nothing to recover.
    expect(
      legacySubjectFromSecret(
        b64({ privateKey: 'x', subject: 'did:ad:agent:NkQ5OoxIzOnKu5Oa' }),
      ),
    ).toBeUndefined();
  });

  it('never throws on a malformed secret', ({ expect }) => {
    // Runs on the sign-in path — it must not be able to break signing in.
    for (const bad of [
      '',
      'not-base64!!',
      btoa('{'),
      btoa('{}'),
      btoa('null'),
    ]) {
      expect(() => legacySubjectFromSecret(bad)).not.toThrow();
      expect(legacySubjectFromSecret(bad)).toBeUndefined();
    }
  });
});
