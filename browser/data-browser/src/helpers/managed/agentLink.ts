// @wc-ignore-file
// Agent link client (atomic-saas #138): tells the control plane which Atomic
// agent the signed-in account uses. Services that only ever see a signature,
// like the integration proxy, can then tell whose account a request is for. A
// sync enrollment links an agent too, but needs a drive and a paid plan or an
// invite; a link needs neither.
//
// FOSS guardrail: like the rest of helpers/managed/*, this runs only under the
// user's managed session; the open-core server never phones home. Without a
// session every call here is a no-op.
//
// Contract: atomic-saas `planning/SAAS_ATOMIC_SERVER_CONTRACT.md`, "Agent link
// without a drive (#138)".

import * as Sentry from '@sentry/react';
import { agentPublicKey, createAuthentication, type Agent } from '@tomic/lib';
import { managedFetch } from './api';
import { getManagedAccount } from './session';

/** The account's agent, as `GET /api/agent-link` answers it. */
export type ManagedAgentLink = {
  /** Always `atomic:agent:` with unpadded base64url. */
  agent_subject: string;
  linked_at: number;
};

/**
 * What `POST /api/agent-link/challenge` hands back. The control plane stores
 * every bound field itself; the client only echoes `nonce` and signs
 * `challenge`.
 */
export type ManagedAgentLinkChallenge = {
  nonce: string;
  challenge: string;
  agent_subject: string;
  expires_at: number;
};

/** The body of `POST /api/agent-link`. */
export type ManagedAgentLinkProof = {
  nonce: string;
  public_key: string;
  timestamp: number;
  signature: string;
};

export type AgentLinkOutcome =
  /** The account had no link, or another agent's, and now has this one. */
  | 'linked'
  /** The account was already linked to this agent. */
  | 'already_linked'
  /** No agent here, or no managed session. */
  | 'skipped'
  /** A control plane from before agent links (404). */
  | 'unsupported'
  /** Only a confirmed email can link: the account never redeemed an email link. */
  | 'email_not_confirmed'
  /** This agent is linked to another account, which has to unlink it first. */
  | 'linked_elsewhere'
  | 'failed';

/**
 * An agent's key in one spelling. Subjects have carried it in both base64
 * alphabets, padded or not, and the control plane answers the canonical
 * unpadded base64url whatever the client sent.
 */
function keyOf(subject: string): string | undefined {
  return agentPublicKey(subject)
    ?.replace(/-/g, '+')
    .replace(/_/g, '/')
    .replace(/=+$/, '');
}

function sameKey(a: string, b: string): boolean {
  const key = keyOf(a);

  return key !== undefined && key === keyOf(b);
}

async function errorCodeOf(response: Response): Promise<string | undefined> {
  const body = (await response.json().catch(() => null)) as {
    error_code?: string;
  } | null;

  return body?.error_code;
}

/** Report what only a bug produces: nobody can fix it from the app. */
function reportBug(error: unknown): void {
  Sentry.captureException(error, { tags: { flow: 'agent-link' } });
}

/**
 * Answer a link challenge with the agent's signature. Signing reuses
 * `createAuthentication`, exactly as the enrollment proof does: the message is
 * `"{challenge} {timestamp}"`, and the challenge's own prefix keeps it from
 * passing as an enrollment proof or as request authentication.
 */
export async function buildAgentLinkProof(
  challenge: ManagedAgentLinkChallenge,
  agent: Agent,
): Promise<ManagedAgentLinkProof> {
  if (!agent.subject || !sameKey(agent.subject, challenge.agent_subject)) {
    throw new Error(
      `The agent link challenge is for ${challenge.agent_subject}, ` +
        `but the signing identity is ${agent.subject}.`,
    );
  }

  const auth = await createAuthentication(challenge.challenge, agent);

  return {
    nonce: challenge.nonce,
    public_key: auth['https://atomicdata.dev/properties/auth/publicKey'],
    timestamp: auth['https://atomicdata.dev/properties/auth/timestamp'],
    signature: auth['https://atomicdata.dev/properties/auth/signature'],
  };
}

async function link(agent: Agent, subject: string): Promise<AgentLinkOutcome> {
  const current = await managedFetch('/agent-link', {});

  if (current.status === 404) return 'unsupported';
  if (current.status === 401) return 'skipped';
  if (!current.ok) return 'failed';

  const existing = (await current.json()) as ManagedAgentLink | null;

  if (existing && sameKey(existing.agent_subject, subject)) {
    return 'already_linked';
  }

  const challengeResponse = await managedFetch('/agent-link/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_subject: subject }),
  });

  if (challengeResponse.status === 404) return 'unsupported';

  if (!challengeResponse.ok) {
    return (await errorCodeOf(challengeResponse)) === 'email_not_confirmed'
      ? 'email_not_confirmed'
      : 'failed';
  }

  const challenge =
    (await challengeResponse.json()) as ManagedAgentLinkChallenge;
  let proof: ManagedAgentLinkProof;

  try {
    proof = await buildAgentLinkProof(challenge, agent);
  } catch (error) {
    reportBug(error);

    return 'failed';
  }

  const response = await managedFetch('/agent-link', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(proof),
  });

  if (response.ok) return 'linked';

  const code = await errorCodeOf(response);

  if (code === 'agent_linked_to_another_account') return 'linked_elsewhere';
  if (code === 'email_not_confirmed') return 'email_not_confirmed';

  if (code === 'agent_link_proof_invalid') {
    reportBug(new Error('The control plane refused an agent link proof'));
  }

  return 'failed';
}

const attempts = new Map<string, Promise<AgentLinkOutcome>>();

/**
 * Link `agent` to the signed-in account. Best-effort, and tried once per app
 * session for each account and agent: a failure waits for the next load
 * rather than repeating on every navigation. Never throws, so callers can
 * fire and forget.
 *
 * A link replaces the account's previous one, so callers pass the agent the
 * account has adopted: the identity reconcile gate does, once it has
 * converged.
 */
export async function linkAgentToAccount(
  agent: Agent | undefined,
): Promise<AgentLinkOutcome> {
  const subject = agent?.subject;

  if (!agent || !subject) return 'skipped';

  const account = await getManagedAccount().catch(() => null);

  if (!account) return 'skipped';

  const key = `${account.email}\n${keyOf(subject) ?? subject}`;
  const pending = attempts.get(key);

  if (pending) return pending;

  const attempt = link(agent, subject)
    // Offline, or an answer that is not JSON (an older control plane serves
    // its own app for paths it does not know): try on the next load.
    .catch((): AgentLinkOutcome => 'failed')
    .then(outcome => {
      // The session ended while linking. A new sign-in should try again.
      if (outcome === 'skipped') attempts.delete(key);

      return outcome;
    });
  attempts.set(key, attempt);

  return attempt;
}

/** Forget this session's attempts. For tests. */
export function resetAgentLinkAttempts(): void {
  attempts.clear();
}
