import { describe, expect, it } from 'vitest';
import { generateInviteToken } from './invites.js';
import { Agent } from './agent.js';
import { server } from './ontologies/server.js';
import { properties } from './urls.js';
import { JSCryptoProvider } from './CryptoProvider.js';

describe('invites', () => {
  it('generates a valid invite token', async () => {
    const validPrivateKey = 'CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=';
    const validSubject = 'https://atomicdata.dev/agents/test';
    const agent = new Agent(
      new JSCryptoProvider(validPrivateKey),
      validSubject,
    );
    const target = 'https://example.com/target';
    const write = true;
    const expiresAt = Date.now() + 10000;

    const tokenBase64 = await generateInviteToken(
      target,
      agent,
      write,
      expiresAt,
    );
    expect(tokenBase64).toBeDefined();

    const decoded = JSON.parse(atob(tokenBase64));
    expect(decoded[server.properties.target]).toBe(target);
    expect(decoded[server.properties.write]).toBe(write);
    expect(decoded['https://atomicdata.dev/properties/invite/expiresAt']).toBe(
      expiresAt,
    );
    expect(decoded[properties.commit.signer]).toBe(agent.subject);
    expect(decoded[properties.commit.signature]).toBeDefined();
  });

  describe('usage limit', () => {
    const makeAgent = () =>
      new Agent(
        new JSCryptoProvider('CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI='),
        'https://atomicdata.dev/agents/test',
      );
    const decode = (t: string) => JSON.parse(atob(t));

    it('signs the limit into the token', async () => {
      const token = await generateInviteToken(
        'https://example.com/target',
        makeAgent(),
        false,
        Date.now() + 10000,
        undefined,
        false,
        1,
      );

      expect(decode(token)[server.properties.usagesLeft]).toBe(1);
    });

    it('leaves the key out when unlimited', async () => {
      const token = await generateInviteToken(
        'https://example.com/target',
        makeAgent(),
      );

      expect(server.properties.usagesLeft in decode(token)).toBe(false);
    });

    it('rejects limits that make no sense', async () => {
      for (const bad of [0, -1, 1.5, NaN]) {
        await expect(
          generateInviteToken(
            'https://example.com/target',
            makeAgent(),
            false,
            undefined,
            undefined,
            false,
            bad,
          ),
        ).rejects.toThrow(/usage limit/);
      }
    });

    it('refuses a limit on a browser-peer invite', async () => {
      await expect(
        generateInviteToken(
          'https://example.com/target',
          makeAgent(),
          false,
          undefined,
          undefined,
          true,
          3,
        ),
      ).rejects.toThrow(/cannot have a usage limit/);
    });
  });
});
