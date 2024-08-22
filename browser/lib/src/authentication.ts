import { Agent } from './agent.js';
import type { HeadersObject } from './client.js';
import { generateKeyPair, getTimestampNow, signToBase64 } from './commit.js';
import type { Store } from './store.js';
import type { Resource } from './resource.js';
import { core } from './ontologies/core.js';

/** Returns a JSON-AD resource of an Authentication */
export async function createAuthentication(subject: string, agent: Agent) {
  const timestamp = getTimestampNow();

  if (!agent.subject) {
    throw new Error('Agent has no subject, cannot authenticate');
  }

  const object = {
    'https://atomicdata.dev/properties/auth/agent': agent.subject,
    'https://atomicdata.dev/properties/auth/requestedSubject': subject,
    'https://atomicdata.dev/properties/auth/publicKey':
      await agent.getPublicKey(),
    'https://atomicdata.dev/properties/auth/timestamp': timestamp,
    'https://atomicdata.dev/properties/auth/signature': await signatureMessage(
      subject,
      agent,
      timestamp,
    ),
  };

  return object;
}

/** Returns a string used to sign requests. */
export async function signatureMessage(
  subject: string,
  agent: Agent,
  timestamp: number,
) {
  const message = `${subject} ${timestamp}`;

  return await signToBase64(message, agent.privateKey);
}

/** Localhost Agents are not allowed to sign requests to external domain */
function localTryingExternal(subject: string, agent: Agent) {
  return (
    !subject.startsWith('http://localhost') &&
    agent?.subject?.startsWith('http://localhost')
  );
}

/**
 * Creates authentication headers and signs the request. Does not add headers if
 * the Agents subject is missing.
 */
export async function signRequest(
  /** The resource meant to be fetched */
  subject: string,
  agent: Agent,
  headers: HeadersObject | Headers,
): Promise<HeadersObject> {
  const timestamp = getTimestampNow();

  if (agent?.subject && !localTryingExternal(subject, agent)) {
    headers['x-atomic-public-key'] = await agent.getPublicKey();
    headers['x-atomic-signature'] = await signatureMessage(
      subject,
      agent,
      timestamp,
    );
    headers['x-atomic-timestamp'] = timestamp;
    headers['x-atomic-agent'] = agent?.subject;
  }

  return headers as HeadersObject;
}

const ONE_DAY = 24 * 60 * 60 * 1000;
const COOKIE_NAME_AUTH = 'atomic_session';

const setCookieExpires = (
  name: string,
  value: string,
  serverUrl: string,
  expires_in_ms = ONE_DAY,
) => {
  const expiry = new Date(Date.now() + expires_in_ms).toUTCString();
  const encodedValue = encodeURIComponent(value);

  const domain = new URL(serverUrl).hostname;

  const cookieString = `${name}=${encodedValue};Expires=${expiry};Domain=${domain};SameSite=Lax;path=/`;
  document.cookie = cookieString;
};

/** Sets a cookie for the current Agent, signing the Authentication. It expires after some default time. */
export const setCookieAuthentication = (serverURL: string, agent: Agent) => {
  createAuthentication(serverURL, agent).then(auth => {
    setCookieExpires(COOKIE_NAME_AUTH, btoa(JSON.stringify(auth)), serverURL);
  });
};

export const removeCookieAuthentication = () => {
  if (typeof document !== 'undefined') {
    document.cookie = `${COOKIE_NAME_AUTH}=;Max-Age=-99999999`;
  }
};

/** Returns false if the auth cookie is not set / expired */
export const checkAuthenticationCookie = (): boolean => {
  const matches = document.cookie.match(
    /^(.*;)?\s*atomic_session\s*=\s*[^;]+(.*)?$/,
  );

  if (!matches) {
    return false;
  }

  return matches.length > 0;
};

/** Only allows lowercase chars and numbers  */
export const nameRegex = '^[a-z0-9_-]+';

export async function serverSupportsRegister(store: Store) {
  const url = new URL('/register', store.getServerUrl());
  const resource = await store.getResource(url.toString());

  if (!resource) {
    return false;
  }

  if (resource.error) {
    return false;
  }

  return true;
}

/** Run this after making a call to an endpoint. Throws if something went wrong. */
function checkResourceSuccess(resource?: Resource) {
  if (!resource) {
    throw new Error('No resource received');
  }

  if (resource.error) {
    throw resource.error;
  }

  const respName = resource.get(core.properties.name) as string;

  if (!respName.includes('Success')) {
    throw new Error('Expected a `success` message, did not receive one');
  }
}

/** Asks the server to create an Agent + a Drive.
 * Sends the confirmation email to the user.
 * Throws if the name is not available or the email is invalid.
 * The Agent and Drive are only created after the Email is confirmed. */
export async function register(
  store: Store,
  name: string,
  email: string,
): Promise<void> {
  const url = new URL('/register', store.getServerUrl());
  url.searchParams.set('name', name);
  url.searchParams.set('email', email);
  const resource = await store.getResourceAsync(url.toString());
  checkResourceSuccess(resource);

  return;
}

/** Asks the server to add a public key to an account. Will lead to a confirmation link being sent */
export async function addPublicKey(store: Store, email: string): Promise<void> {
  if (!email) {
    throw new Error('No email provided');
  }

  const url = new URL('/add-public-key', store.getServerUrl());
  url.searchParams.set('email', email);
  const resource = await store.getResourceAsync(url.toString());
  checkResourceSuccess(resource);

  return;
}

/** When the user receives a confirmation link, call this function with the provided URL.
 * If there is no agent in the store, a new one will be created.  */
export async function confirmEmail(
  store: Store,
  /** Full http URL including the `token` query parameter */
  tokenURL: string,
): Promise<{ agent: Agent; destination: string }> {
  const url = new URL(tokenURL);
  const token = url.searchParams.get('token');

  if (!token) {
    throw new Error('No token provided');
  }

  const parsed = parseJwt(token);

  if (!parsed.name || !parsed.email) {
    throw new Error('token does not contain name or email');
  }

  let agent = store.getAgent();

  // No agent, create a new one
  if (!agent) {
    const keypair = await generateKeyPair();
    const newAgent = new Agent(keypair.privateKey);
    newAgent.subject = `${store.getServerUrl()}/agents/${parsed.name}`;
    agent = newAgent;
  }

  // An agent already exists, make sure it matches the confirm email token
  if (!agent?.subject?.includes(parsed.name)) {
    throw new Error(
      'You cannot confirm this email, you are already logged in as a different user',
    );
  }

  url.searchParams.set('public-key', await agent.getPublicKey());
  const resource = await store.getResource(url.toString());

  if (!resource) {
    throw new Error('no resource!');
  }

  if (resource.error) {
    throw resource.error;
  }

  const destination = resource.get(
    'https://atomicdata.dev/properties/destination',
  ) as string;

  if (!destination) {
    throw new Error('No redirect destination in response');
  }

  store.setAgent(agent);

  return { agent, destination };
}

function parseJwt(token: string) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      window
        .atob(base64)
        .split('')
        .map(function (c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        })
        .join(''),
    );

    return JSON.parse(jsonPayload);
  } catch (e) {
    throw new Error('Invalid token: ' + e);
  }
}
