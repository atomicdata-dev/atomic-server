import { describe, it } from 'vitest';
import { Agent } from './agent.js';
import {
  agentSubjectForAuth,
  createAuthentication,
  signRequest,
} from './authentication.js';

const AUTH_AGENT = 'https://atomicdata.dev/properties/auth/agent';

/**
 * A browser on `atomic:` talking to a node that predates the scheme: the node
 * reads `atomic:agent:{key}` as an external URL and answers "Agent subject ...
 * is hosted elsewhere" (ATOMIC-BROWSER-36). The AUTH proof is sent before the
 * server's capabilities are known, so it must use the spelling every node
 * parses.
 */
describe('agent spelling in auth proofs', () => {
  const makeAgent = async () => {
    const agent = await Agent.generateNonExtractable();

    return { agent, publicKey: await agent.getPublicKey() };
  };

  it('keeps the agent canonical (atomic:) locally', async ({ expect }) => {
    const { agent, publicKey } = await makeAgent();

    expect(agent.subject).toBe(`atomic:agent:${publicKey}`);
  });

  it('sends did:ad:agent: in the WebSocket AUTH payload', async ({
    expect,
  }) => {
    const { agent, publicKey } = await makeAgent();
    const proof = await createAuthentication(
      'http://localhost:9883#nonce',
      agent,
    );

    expect(proof[AUTH_AGENT]).toBe(`did:ad:agent:${publicKey}`);
    expect(agent.subject).toBe(`atomic:agent:${publicKey}`);
  });

  it('sends did:ad:agent: in version 1 request headers', async ({ expect }) => {
    const { agent, publicKey } = await makeAgent();
    const headers = await signRequest(
      'http://localhost:9883/server',
      agent,
      {},
    );

    expect(headers['x-atomic-agent']).toBe(`did:ad:agent:${publicKey}`);
  });

  it('leaves version 2 request headers canonical', async ({ expect }) => {
    const { agent } = await makeAgent();
    const headers = await signRequest(
      'http://localhost:9883/x',
      agent,
      {},
      { method: 'POST', body: '{}' },
    );

    expect(headers['x-atomic-agent']).toBe(agent.subject);
  });

  it('only rewrites the scheme prefix', ({ expect }) => {
    expect(agentSubjectForAuth('atomic:agent:abc_-')).toBe(
      'did:ad:agent:abc_-',
    );
    expect(agentSubjectForAuth('did:ad:agent:abc')).toBe('did:ad:agent:abc');
    expect(agentSubjectForAuth('https://example.com/agents/abc')).toBe(
      'https://example.com/agents/abc',
    );
  });
});
