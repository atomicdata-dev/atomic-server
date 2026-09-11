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
 */
export async function generateInviteToken(
  target: string,
  agent: Agent,
  write = false,
  expiresAt?: number,
  description?: string,
  browserPeer = false,
): Promise<string> {
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
