import stringify from 'fast-json-stable-stringify';
import { verify } from '@noble/ed25519';
import { decodeB64 } from './base64.js';
import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import { properties } from './urls.js';
import type { Store } from './store.js';

const AUTH = 'https://atomicdata.dev/properties/auth/';
const EXPIRES = 'https://atomicdata.dev/properties/invite/expiresAt';

/** Verify locally without fetching an issuer profile from a data server. */
export function decodeBrowserInvite(token: string) {
  if (token.length > 4096) throw new Error('Invite is too large');
  const data = JSON.parse(atob(token));
  const drive = data[server.properties.target];
  const issuer = data[properties.commit.signer];
  if (
    typeof drive !== 'string' ||
    !drive.startsWith('did:ad:') ||
    /[?#]/.test(drive) ||
    typeof issuer !== 'string' ||
    !issuer.startsWith('did:ad:agent:') ||
    typeof data[server.properties.write] !== 'boolean' ||
    !Number.isSafeInteger(data[EXPIRES]) ||
    data[EXPIRES] <= Date.now()
  )
    throw new Error('Invalid or expired browser invite');
  const signature = data[properties.commit.signature];
  delete data[properties.commit.signature];
  if (
    typeof signature !== 'string' ||
    !verify(
      decodeB64(signature),
      new TextEncoder().encode(stringify(data)),
      decodeB64(issuer.slice('did:ad:agent:'.length)),
    )
  )
    throw new Error('Invalid invite signature');

  return { drive, issuer, write: data[server.properties.write] as boolean };
}

/** The issuer grants rights through a normal signed commit, never an unsafe
 * snapshot edit. Called before Rust AUTH, which independently checks the grant.
 * The bearer token is released only after the recipient authenticates the issuer. */
export async function authorizeBrowserInvite(
  store: Store,
  drive: string,
  token: string,
  auth: Record<string, unknown>,
  challenge: string,
): Promise<void> {
  const invite = decodeBrowserInvite(token);
  const issuer = store.getAgent();
  if (invite.drive !== drive || invite.issuer !== issuer?.subject)
    throw new Error('This browser cannot accept that invitation');
  const recipient = auth[`${AUTH}agent`];
  const timestamp = auth[`${AUTH}timestamp`];
  const signature = auth[`${AUTH}signature`];
  if (
    typeof recipient !== 'string' ||
    !recipient.startsWith('did:ad:agent:') ||
    auth[`${AUTH}requestedSubject`] !== challenge ||
    auth[`${AUTH}publicKey`] !== recipient.slice('did:ad:agent:'.length) ||
    typeof timestamp !== 'number' ||
    !Number.isSafeInteger(timestamp) ||
    Math.abs(Date.now() - timestamp) > 60000 ||
    typeof signature !== 'string' ||
    !verify(
      decodeB64(signature),
      new TextEncoder().encode(`${challenge} ${timestamp}`),
      decodeB64(recipient.slice('did:ad:agent:'.length)),
    )
  )
    throw new Error('Invalid invite recipient authentication');
  const resource = store.resources.get(drive);
  if (
    !resource?.isReady() ||
    !resource.hasClasses(server.classes.drive) ||
    !(await resource.canWrite(issuer.subject))[0]
  )
    throw new Error('Invite issuer no longer has access');
  if (store.getAgent() !== issuer) throw new Error('Account changed');
  resource.push(core.properties.read, [recipient], true);
  if (invite.write) resource.push(core.properties.write, [recipient], true);
  await resource.save();
  await store.getClientDb()?.flush();
}
