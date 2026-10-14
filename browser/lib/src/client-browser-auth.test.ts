import { afterEach, expect, it, vi } from 'vitest';
import { Agent } from './agent.js';
import { Client } from './client.js';
import { JSCryptoProvider } from './CryptoProvider.js';

const origin = 'http://localhost:6747';
const target = `${origin}/invites?token=example`;

afterEach(() => vi.unstubAllGlobals());

function browserWithOtherSession() {
  vi.stubGlobal('window', globalThis);
  vi.stubGlobal('location', { origin });
  vi.stubGlobal('document', {
    cookie: `atomic_session=${btoa(
      JSON.stringify({
        'https://atomicdata.dev/properties/auth/timestamp': Date.now(),
        'https://atomicdata.dev/properties/auth/requestedSubject':
          'http://localhost:9883',
        'https://atomicdata.dev/properties/signer':
          'atomic:agent:previous-user',
      }),
    )}`,
  });
}

it('binds a same-origin request to its current agent and URL despite another fresh cookie', async () => {
  browserWithOtherSession();
  const keys = await Agent.generateKeyPair();
  const agent = new Agent(
    new JSCryptoProvider(keys.privateKey),
    `atomic:agent:${keys.publicKey}`,
  );
  const signature = vi.spyOn(agent, 'createSignature');
  let sent: RequestInit | undefined;
  const client = new Client(async (_url, init) => {
    sent = init;

    return new Response(JSON.stringify({ '@id': target }));
  });
  const { resource } = await client.fetchResourceHTTP(target, {
    method: 'POST',
    signInfo: { agent, serverURL: 'http://localhost:9883' },
  });
  expect(resource.error).toBeUndefined();
  expect(new Headers(sent?.headers).get('x-atomic-agent')).toBe(agent.subject);
  expect(signature).toHaveBeenCalledWith(target, expect.any(Number));
  expect(sent?.credentials).toBe('omit');
});

it('an anonymous read cannot inherit the previous account through ambient cookies', async () => {
  browserWithOtherSession();
  let sent: RequestInit | undefined;
  const client = new Client(async (_url, init) => {
    sent = init;

    return new Response(JSON.stringify({ '@id': target }));
  });
  await client.fetchResourceHTTP(target);
  expect(new Headers(sent?.headers).get('x-atomic-agent')).toBeNull();
  expect(sent?.credentials).toBe('omit');
});
