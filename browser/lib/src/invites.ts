import stringify from 'fast-json-stable-stringify';
import { Agent } from './agent.js';
import { server } from './ontologies/server.js';
import { core } from './ontologies/core.js';
import { properties } from './urls.js';

/**
 * Generates a signed, stateless invite token.
 *
 * `description` is an optional free-text note the inviter adds (e.g. "come
 * review the Q3 plan"). Included in the signed payload so recipients see
 * exactly what the inviter wrote.
 *
 * `maxUsages` limits how many different agents may accept the invite. The
 * server enforces it (it is part of the signed payload, so it cannot be
 * raised afterwards). Omit it for an unlimited invite. Invites that never
 * reach a server (`browserPeer`) cannot be limited.
 */
export async function generateInviteToken(
  target: string,
  agent: Agent,
  write = false,
  expiresAt?: number,
  description?: string,
  browserPeer = false,
  maxUsages?: number,
): Promise<string> {
  if (
    maxUsages !== undefined &&
    (!Number.isSafeInteger(maxUsages) || maxUsages < 1)
  )
    throw new Error(
      'The usage limit of an invite must be a whole number of at least 1.',
    );

  if (maxUsages !== undefined && browserPeer)
    throw new Error(
      'Invites to a drive that syncs between browsers cannot have a usage limit.',
    );

  const expires = expiresAt ?? Date.now() + 1000 * 60 * 60 * 24 * 30; // 30 days default

  const signable: Record<string, unknown> = {
    [server.properties.target]: target,
    [server.properties.write]: write,
    ['https://atomicdata.dev/properties/invite/expiresAt']: expires,
    [properties.commit.signer]: agent.subject,
  };

  // Only include the description key when actually set — keeps old tokens
  // (without description) deterministically serializing the same way.
  if (description && description.trim().length > 0) {
    signable[core.properties.description] = description.trim();
  }

  if (maxUsages !== undefined)
    signable[server.properties.usagesLeft] = maxUsages;

  if (browserPeer)
    signable['https://atomicdata.dev/properties/invite/transport'] = 'webrtc';

  const serialized = stringify(signable);
  const signature = await agent.sign(serialized);

  const token = {
    ...signable,
    [properties.commit.signature]: signature,
  };

  return btoa(JSON.stringify(token));
}
