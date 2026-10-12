import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Agent, JSCryptoProvider, decodeB64 } from '@tomic/lib';

const managedFetch = vi.fn();
const getManagedAccount = vi.fn();
const captureException = vi.fn();
vi.mock('./api', () => ({
  managedFetch: (...a: unknown[]) => managedFetch(...a),
}));
vi.mock('./session', () => ({
  getManagedAccount: () => getManagedAccount(),
}));
vi.mock('@sentry/react', () => ({
  captureException: (...a: unknown[]) => captureException(...a),
}));

const { linkAgentToAccount, buildAgentLinkProof, resetAgentLinkAttempts } =
  await import('./agentLink');

// Made for each run: secret scanners read a key written into the source as a
// leaked one, and nothing here depends on which key it is.
const { privateKey: PRIVATE_KEY } = await Agent.generateKeyPair();

/** `prefix` + the key in the spelling `@tomic/lib` writes today: unpadded base64url. */
async function testAgent(prefix = 'atomic:agent:'): Promise<Agent> {
  const provider = new JSCryptoProvider(PRIVATE_KEY);

  return new Agent(provider, `${prefix}${await provider.getPublicKey()}`);
}

/** The same key in the standard alphabet with padding, as older secrets carry it. */
const standardSpelling = (b64url: string) =>
  b64url.replace(/-/g, '+').replace(/_/g, '/') +
  '='.repeat((4 - (b64url.length % 4)) % 4);

const canonical = async () =>
  `atomic:agent:${await (await testAgent()).getPublicKey()}`;

const respond = (status: number, body: unknown) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
});

const challengeFor = (agentSubject: string) => ({
  nonce: 'nonce-1',
  challenge: `atomic-saas:agent-link:v1:nonce-1:${agentSubject}:acct_1:1900000000`,
  agent_subject: agentSubject,
  expires_at: 1900000000,
});

/** Answer each control plane route; anything else is a test failure. */
function controlPlane(routes: {
  get?: () => unknown;
  challenge?: (body: { agent_subject: string }) => unknown;
  link?: (body: Record<string, unknown>) => unknown;
}) {
  managedFetch.mockImplementation(
    async (path: string, init: { method?: string; body?: string }) => {
      const body = init.body ? JSON.parse(init.body) : undefined;
      const route =
        path === '/agent-link' && !init.method
          ? routes.get
          : path === '/agent-link/challenge'
            ? routes.challenge
            : path === '/agent-link' && init.method === 'POST'
              ? routes.link
              : undefined;

      if (!route) throw new Error(`unexpected ${init.method ?? 'GET'} ${path}`);

      return route(body);
    },
  );
}

const calls = () =>
  managedFetch.mock.calls.map(
    ([path, init]) =>
      `${(init as { method?: string }).method ?? 'GET'} ${path}`,
  );

/** Verify an Ed25519 signature with WebCrypto, independent of `@tomic/lib`'s signer. */
async function verifies(
  publicKeyB64: string,
  message: string,
  signatureB64: string,
): Promise<boolean> {
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    Uint8Array.from(decodeB64(publicKeyB64)),
    { name: 'Ed25519' },
    false,
    ['verify'],
  );

  return globalThis.crypto.subtle.verify(
    { name: 'Ed25519' },
    key,
    Uint8Array.from(decodeB64(signatureB64)),
    new TextEncoder().encode(message),
  );
}

beforeEach(() => {
  managedFetch.mockReset();
  captureException.mockReset();
  getManagedAccount.mockReset();
  getManagedAccount.mockResolvedValue({ email: 'acct_1' });
  resetAgentLinkAttempts();
});

describe('linkAgentToAccount', () => {
  it('links an unlinked account with a proof the control plane can check', async () => {
    const agent = await testAgent();
    let sent: Record<string, unknown> | undefined;
    controlPlane({
      get: () => respond(200, null),
      challenge: ({ agent_subject }) =>
        respond(200, challengeFor(agent_subject)),
      link: body => {
        sent = body;

        return respond(200, {
          agent_subject: agent.subject,
          linked_at: 1,
        });
      },
    });

    expect(await linkAgentToAccount(agent)).toBe('linked');
    expect(calls()).toEqual([
      'GET /agent-link',
      'POST /agent-link/challenge',
      'POST /agent-link',
    ]);
    expect(sent?.nonce).toBe('nonce-1');
    expect(sent?.public_key).toBe(await agent.getPublicKey());
    expect(
      await verifies(
        sent?.public_key as string,
        `${challengeFor(agent.subject!).challenge} ${sent?.timestamp}`,
        sent?.signature as string,
      ),
    ).toBe(true);
  });

  /**
   * The control plane answers the canonical spelling whatever it was sent, and
   * older identities carry the key padded, in the standard alphabet, under
   * `did:ad:`. Read as different agents, every load would link again.
   */
  it('recognises its own agent in the canonical spelling', async () => {
    const key = await (await testAgent()).getPublicKey();
    const agent = new Agent(
      new JSCryptoProvider(PRIVATE_KEY),
      `did:ad:agent:${standardSpelling(key)}`,
    );
    const linked = { agent_subject: await canonical(), linked_at: 1 };
    controlPlane({ get: () => respond(200, linked) });

    expect(await linkAgentToAccount(agent)).toBe('already_linked');
    expect(calls()).toEqual(['GET /agent-link']);
  });

  it('signs a challenge that names its agent in another spelling', async () => {
    const key = await (await testAgent()).getPublicKey();
    const agent = new Agent(
      new JSCryptoProvider(PRIVATE_KEY),
      `did:ad:agent:${standardSpelling(key)}`,
    );
    const challenge = challengeFor(await canonical());

    const proof = await buildAgentLinkProof(challenge, agent);

    expect(
      await verifies(
        proof.public_key,
        `${challenge.challenge} ${proof.timestamp}`,
        proof.signature,
      ),
    ).toBe(true);
  });

  /** A link replaces the account's previous one, as agreed on atomic-saas #138. */
  it("replaces a link to another agent with this device's agent", async () => {
    const agent = await testAgent();
    controlPlane({
      get: () =>
        respond(200, {
          agent_subject: 'atomic:agent:someoneElsesKey',
          linked_at: 1,
        }),
      challenge: ({ agent_subject }) =>
        respond(200, challengeFor(agent_subject)),
      link: () => respond(200, { agent_subject: agent.subject, linked_at: 2 }),
    });

    expect(await linkAgentToAccount(agent)).toBe('linked');
  });

  it('does nothing without a session or an agent', async () => {
    getManagedAccount.mockResolvedValue(null);
    expect(await linkAgentToAccount(await testAgent())).toBe('skipped');
    expect(await linkAgentToAccount(undefined)).toBe('skipped');
    expect(managedFetch).not.toHaveBeenCalled();
  });

  it('leaves an older control plane alone', async () => {
    controlPlane({ get: () => respond(404, null) });
    expect(await linkAgentToAccount(await testAgent())).toBe('unsupported');
    expect(calls()).toEqual(['GET /agent-link']);
  });

  it('waits for a confirmed email', async () => {
    controlPlane({
      get: () => respond(200, null),
      challenge: () =>
        respond(403, {
          error: 'Confirm your email address first',
          error_code: 'email_not_confirmed',
        }),
    });

    expect(await linkAgentToAccount(await testAgent())).toBe(
      'email_not_confirmed',
    );
    expect(captureException).not.toHaveBeenCalled();
  });

  it('leaves an agent that another account holds where it is', async () => {
    controlPlane({
      get: () => respond(200, null),
      challenge: ({ agent_subject }) =>
        respond(200, challengeFor(agent_subject)),
      link: () =>
        respond(409, { error_code: 'agent_linked_to_another_account' }),
    });

    expect(await linkAgentToAccount(await testAgent())).toBe(
      'linked_elsewhere',
    );
    expect(captureException).not.toHaveBeenCalled();
  });

  /** Only a bug gets a proof refused, so it is reported rather than shown. */
  it('reports a refused proof', async () => {
    controlPlane({
      get: () => respond(200, null),
      challenge: ({ agent_subject }) =>
        respond(200, challengeFor(agent_subject)),
      link: () => respond(403, { error_code: 'agent_link_proof_invalid' }),
    });

    expect(await linkAgentToAccount(await testAgent())).toBe('failed');
    expect(captureException).toHaveBeenCalledOnce();
  });

  it('never signs a challenge issued for another agent', async () => {
    controlPlane({
      get: () => respond(200, null),
      challenge: () => respond(200, challengeFor('atomic:agent:someoneElse')),
    });

    expect(await linkAgentToAccount(await testAgent())).toBe('failed');
    expect(calls()).not.toContain('POST /agent-link');
    expect(captureException).toHaveBeenCalledOnce();
  });

  it('swallows a network failure without reporting it', async () => {
    managedFetch.mockRejectedValue(new TypeError('Failed to fetch'));
    expect(await linkAgentToAccount(await testAgent())).toBe('failed');
    expect(captureException).not.toHaveBeenCalled();
  });

  /**
   * The reconcile gate calls this on every navigation. One attempt per
   * account and agent keeps that from becoming a request per click, and
   * concurrent calls share it.
   */
  it('tries once per session, and shares an attempt in flight', async () => {
    controlPlane({ get: () => respond(500, null) });
    const agent = await testAgent();

    const [first, second] = await Promise.all([
      linkAgentToAccount(agent),
      linkAgentToAccount(agent),
    ]);
    expect(await linkAgentToAccount(agent)).toBe('failed');

    expect([first, second]).toEqual(['failed', 'failed']);
    expect(calls()).toEqual(['GET /agent-link']);
  });

  it('tries again once a lapsed session is signed in again', async () => {
    controlPlane({ get: () => respond(401, null) });
    const agent = await testAgent();
    expect(await linkAgentToAccount(agent)).toBe('skipped');

    controlPlane({
      get: () => respond(200, { agent_subject: agent.subject, linked_at: 1 }),
    });
    expect(await linkAgentToAccount(agent)).toBe('already_linked');
  });
});
