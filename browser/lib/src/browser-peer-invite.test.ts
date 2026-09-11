import { expect, it, vi } from 'vitest';
import { Agent } from './agent.js';
import { generateInviteToken } from './invites.js';
import { createAuthentication } from './authentication.js';
import { authorizeBrowserInvite } from './browser-peer-invite.js';
import type { Store } from './store.js';

async function newAgent() {
  const keys = await Agent.generateKeyPair();

  return Agent.fromSecret(
    Agent.buildSecret(keys.privateKey, `did:ad:agent:${keys.publicKey}`),
  );
}

async function fixture() {
  const issuer = await newAgent();
  const recipient = await newAgent();
  const drive = 'did:ad:private-drive';
  const challenge = `${drive}#channel-bound-challenge`;
  const resource = {
    isReady: () => true,
    canWrite: async () => [true],
    push: vi.fn(),
    save: vi.fn(),
    hasClasses: () => true,
  };
  const store = {
    getAgent: () => issuer,
    resources: new Map([[drive, resource]]),
    getClientDb: () => ({ flush: vi.fn() }),
  } as unknown as Store;
  const token = await generateInviteToken(drive, issuer, true);
  const auth = await createAuthentication(challenge, recipient);

  return { issuer, recipient, drive, challenge, resource, store, token, auth };
}

it('grants a valid invite to the identity proving this channel, with a signed save', async () => {
  const f = await fixture();
  await authorizeBrowserInvite(f.store, f.drive, f.token, f.auth, f.challenge);
  expect(f.resource.push).toHaveBeenCalledWith(
    'https://atomicdata.dev/properties/read',
    [f.recipient.subject],
    true,
  );
  expect(f.resource.push).toHaveBeenCalledWith(
    'https://atomicdata.dev/properties/write',
    [f.recipient.subject],
    true,
  );
  expect(f.resource.save).toHaveBeenCalledOnce();
});
it.each([
  'expired',
  'wrong-drive',
  'wrong-channel',
  'forged',
  'revoked',
  'wrong-recipient',
])('rejects %s before granting access', async kind => {
  const f = await fixture();
  if (kind === 'expired')
    f.token = await generateInviteToken(
      f.drive,
      f.issuer,
      true,
      Date.now() - 1000,
    );
  if (kind === 'wrong-drive')
    f.token = await generateInviteToken('did:ad:other', f.issuer, true);
  if (kind === 'wrong-channel') f.challenge += 'other';

  if (kind === 'forged') {
    const token = JSON.parse(atob(f.token));
    token['https://atomicdata.dev/properties/invite/write'] = false;
    f.token = btoa(JSON.stringify(token));
  }

  if (kind === 'revoked') f.resource.canWrite = async () => [false];
  if (kind === 'wrong-recipient')
    f.auth['https://atomicdata.dev/properties/auth/agent'] = f.issuer.subject!;
  await expect(
    authorizeBrowserInvite(f.store, f.drive, f.token, f.auth, f.challenge),
  ).rejects.toThrow();
  expect(f.resource.push).not.toHaveBeenCalled();
});

it('a viewer invitation grants read access only', async () => {
  const f = await fixture();
  f.token = await generateInviteToken(f.drive, f.issuer, false);
  await authorizeBrowserInvite(f.store, f.drive, f.token, f.auth, f.challenge);
  expect(f.resource.push).toHaveBeenCalledTimes(1);
  expect(f.resource.push).toHaveBeenCalledWith(
    'https://atomicdata.dev/properties/read',
    [f.recipient.subject],
    true,
  );
});
it('does not accept an invitation issued by another identity', async () => {
  const f = await fixture();
  f.token = await generateInviteToken(f.drive, f.recipient, true);
  await expect(
    authorizeBrowserInvite(f.store, f.drive, f.token, f.auth, f.challenge),
  ).rejects.toThrow();
  expect(f.resource.push).not.toHaveBeenCalled();
});
