import {
  Agent,
  getTimestampNow,
  HeadersObject,
  signToBase64,
} from './index.js';

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

const COOKIE_NAME_AUTH = 'atomic_session';

/** Sets a cookie for the current Agent, signing the Authentication. It expires after some default time. */
export const setCookieAuthentication = (serverURL: string, agent: Agent) => {
  createAuthentication(serverURL, agent).then(auth => {
    setCookieExpires(COOKIE_NAME_AUTH, btoa(JSON.stringify(auth)), serverURL);
  });
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

export const removeCookieAuthentication = () => {
  document.cookie = `${COOKIE_NAME_AUTH}=;Max-Age=-99999999`;
};
