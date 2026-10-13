import { type Agent, createAuthentication } from '@tomic/lib';
import {
  getManagedApiBase,
  getManagedDeviceToken,
  hasManagedApi,
  managedFetch,
} from './api';
import { readManagedAccountBinding } from './binding';
import { canHoldProviderCookie } from './deviceLink';
import { readCachedBackups, sameAgent } from './recovery';
import { getManagedAccount, noteManagedSessionChanged } from './session';

/**
 * One sign-in for the app and the account: the identity this device has
 * unlocked also signs the account in, so nobody is signed in on one side and
 * out on the other. The account's own secret sign-in does the work
 * (`POST /api/auth/agent`): the control plane issues a challenge for the
 * agent, the key signs it the way `@tomic/lib` signs any request, and the
 * account linked to that agent gets the shared session cookie.
 *
 * The cookie is the only session this can make, so a device that holds a
 * bearer token instead (the desktop and Android apps) is left to device
 * linking. A self-hosted node has no account to sign in to.
 */

type Challenge = { nonce: string; challenge: string };

/** Agents already tried on this page load, so a refusal is not repeated. */
const attempted = new Set<string>();

/** Only for tests. */
export function resetAgentSessionAttempts(): void {
  attempted.clear();
}

/**
 * Whether this agent is known here as an account's identity: the account
 * binding names it, or this device holds the account's backup of it. A demo
 * guest or a local-only identity has neither, and is never sent to the
 * account server.
 */
function knownAccountIdentity(agentSubject: string): boolean {
  const binding = readManagedAccountBinding();
  if (binding && sameAgent(binding.expected_agent_subject, agentSubject))
    return true;

  return readCachedBackups().some(backup =>
    sameAgent(backup.agent_subject, agentSubject),
  );
}

function portalOrigin(): string | null {
  try {
    return new URL(getManagedApiBase()).origin;
  } catch {
    return null;
  }
}

/**
 * Sign the account in with `agent` when it has no session yet. True when a
 * session now exists. `proven` skips the check that the agent is an account's
 * identity: the person just unlocked it, so asking costs one request at most.
 */
export async function signInAccountWithAgent(
  agent: Agent | undefined,
  { proven = false }: { proven?: boolean } = {},
): Promise<boolean> {
  const subject = agent?.subject;
  if (!agent || !subject) return false;
  if (!hasManagedApi() || getManagedDeviceToken()) return false;
  if (!canHoldProviderCookie(portalOrigin())) return false;
  if (attempted.has(subject)) return false;
  if (!proven && !knownAccountIdentity(subject)) return false;

  attempted.add(subject);

  try {
    if (await getManagedAccount()) return true;

    const issued = await managedFetch('/auth/agent/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_subject: subject }),
    });
    if (!issued.ok) return false;
    const challenge = (await issued.json()) as Partial<Challenge>;
    if (
      typeof challenge?.nonce !== 'string' ||
      typeof challenge.challenge !== 'string'
    )
      return false;

    const auth = await createAuthentication(challenge.challenge, agent);
    const signedIn = await managedFetch('/auth/agent?if_linked=true', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nonce: challenge.nonce,
        timestamp: auth['https://atomicdata.dev/properties/auth/timestamp'],
        signature: auth['https://atomicdata.dev/properties/auth/signature'],
      }),
    });
    // Only 204 establishes a session. A verified identity without an account
    // returns 200 with signed_in:false; no follow-up account read is needed.
    if (signedIn.status !== 204) return false;

    noteManagedSessionChanged();

    return !!(await getManagedAccount());
  } catch {
    // Unreachable or refused: the app works without the account session.
    return false;
  }
}
