// @wc-ignore-file
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { Agent } from '@tomic/lib';
import {
  resetAgentSessionAttempts,
  signInAccountWithAgent,
} from './agentSession';
import { getManagedAccount } from './session';
import {
  getManagedApiBase,
  getManagedDeviceToken,
  hasManagedApi,
  managedFetch,
} from './api';
import { readManagedAccountBinding } from './binding';
import { canHoldProviderCookie } from './deviceLink';
import { readCachedBackups } from './recovery';

vi.mock('./session', () => ({
  getManagedAccount: vi.fn(),
  noteManagedSessionChanged: vi.fn(),
}));
vi.mock('./api', () => ({
  getManagedApiBase: vi.fn(),
  getManagedDeviceToken: vi.fn(),
  hasManagedApi: vi.fn(),
  managedFetch: vi.fn(),
}));
vi.mock('./binding', () => ({ readManagedAccountBinding: vi.fn() }));
vi.mock('./deviceLink', () => ({ canHoldProviderCookie: vi.fn() }));
vi.mock('./recovery', () => ({
  readCachedBackups: vi.fn(),
  sameAgent: (a: string, b: string) => a === b,
}));

let agent: Agent;

beforeEach(async () => {
  resetAgentSessionAttempts();
  const keys = await Agent.generateKeyPair();
  agent = Agent.fromSecret(
    Agent.buildSecret(keys.privateKey, `did:ad:agent:${keys.publicKey}`),
    'js',
  );
  vi.mocked(hasManagedApi).mockReturnValue(true);
  vi.mocked(getManagedApiBase).mockReturnValue('https://atomic.place/api');
  vi.mocked(getManagedDeviceToken).mockReturnValue(null);
  vi.mocked(canHoldProviderCookie).mockReturnValue(true);
  vi.mocked(readManagedAccountBinding).mockReturnValue({
    owner_email: 'one@example.com',
    expected_agent_subject: agent.subject!,
  });
  vi.mocked(readCachedBackups).mockReturnValue([]);
  vi.mocked(getManagedAccount).mockResolvedValue(null);
});

afterEach(() => vi.resetAllMocks());

function answerChallenge(signIn: Response) {
  vi.mocked(managedFetch).mockImplementation(async path =>
    path === '/auth/agent/challenge'
      ? Response.json({ nonce: 'n1', challenge: 'atomic-signin n1 x 9' })
      : signIn,
  );
}

it('signs the account in with the unlocked identity', async () => {
  answerChallenge(new Response(null, { status: 204 }));
  vi.mocked(getManagedAccount)
    .mockResolvedValueOnce(null)
    .mockResolvedValueOnce({ email: 'one@example.com' });

  expect(await signInAccountWithAgent(agent)).toBe(true);

  const [, signIn] = vi.mocked(managedFetch).mock.calls;
  expect(signIn[0]).toBe('/auth/agent?if_linked=true');
  const body = JSON.parse(signIn[1]!.body as string);
  expect(body.nonce).toBe('n1');
  expect(typeof body.signature).toBe('string');
  expect(typeof body.timestamp).toBe('number');
});

it('leaves an existing session alone', async () => {
  vi.mocked(getManagedAccount).mockResolvedValue({ email: 'one@example.com' });

  expect(await signInAccountWithAgent(agent)).toBe(true);
  expect(managedFetch).not.toHaveBeenCalled();
});

it('never sends an identity that is not an account identity', async () => {
  vi.mocked(readManagedAccountBinding).mockReturnValue(null);

  expect(await signInAccountWithAgent(agent)).toBe(false);
  expect(managedFetch).not.toHaveBeenCalled();
  expect(getManagedAccount).not.toHaveBeenCalled();
});

it('tries a just-unlocked identity once, and not again after a refusal', async () => {
  vi.mocked(readManagedAccountBinding).mockReturnValue(null);
  answerChallenge(new Response(null, { status: 404 }));

  expect(await signInAccountWithAgent(agent, { proven: true })).toBe(false);
  expect(await signInAccountWithAgent(agent, { proven: true })).toBe(false);
  expect(managedFetch).toHaveBeenCalledTimes(2);
});

it('treats a verified local identity without an account as a normal result', async () => {
  vi.mocked(readManagedAccountBinding).mockReturnValue(null);
  answerChallenge(Response.json({ signed_in: false }));

  expect(await signInAccountWithAgent(agent, { proven: true })).toBe(false);
  expect(vi.mocked(managedFetch).mock.calls[1][0]).toBe(
    '/auth/agent?if_linked=true',
  );
  expect(getManagedAccount).toHaveBeenCalledTimes(1);
});

it('does nothing where the account cookie cannot live', async () => {
  vi.mocked(canHoldProviderCookie).mockReturnValue(false);
  expect(await signInAccountWithAgent(agent)).toBe(false);

  vi.mocked(canHoldProviderCookie).mockReturnValue(true);
  vi.mocked(getManagedDeviceToken).mockReturnValue('device-token');
  expect(await signInAccountWithAgent(agent)).toBe(false);

  vi.mocked(getManagedDeviceToken).mockReturnValue(null);
  vi.mocked(hasManagedApi).mockReturnValue(false);
  expect(await signInAccountWithAgent(agent)).toBe(false);

  expect(managedFetch).not.toHaveBeenCalled();
});

it('ignores an answer that is not a challenge', async () => {
  vi.mocked(managedFetch).mockResolvedValue(Response.json([]));

  expect(await signInAccountWithAgent(agent)).toBe(false);
  expect(managedFetch).toHaveBeenCalledTimes(1);
});
