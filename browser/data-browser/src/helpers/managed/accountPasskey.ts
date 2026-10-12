// @wc-ignore-file
import { hasManagedApi, managedFetch } from './api';
import { getManagedAccount, noteManagedSessionChanged } from './session';

function decode(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c =>
    c.charCodeAt(0),
  );
}

function encode(value: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function request(path: string, body?: unknown, ceremony?: string) {
  const response = await managedFetch(
    `/passkeys${path}`,
    body === undefined
      ? {}
      : {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            // A linked device has no ceremony cookie, so the id travels back
            // in a header. The portal still accepts the cookie.
            ...(ceremony ? { 'X-Passkey-Ceremony': ceremony } : {}),
          },
          body: JSON.stringify(body),
        },
  );
  if (!response.ok)
    throw new Error(
      `Could not set up your account passkey. Sign in to your account and try again. (${path || '/status'}: ${response.status})`,
    );

  return response.status === 204 ? undefined : response.json();
}

/** Serialize only authentication data. PRF outputs must never leave this browser. */
export function authenticationResponse(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: encode(credential.rawId),
    rawId: encode(credential.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: encode(response.clientDataJSON),
      authenticatorData: encode(response.authenticatorData),
      signature: encode(response.signature),
      userHandle: response.userHandle ? encode(response.userHandle) : null,
    },
    clientExtensionResults: {},
  };
}

/** A managed account reuses its login credential; standalone recovery stays local. */
export async function accountPasskey(
  prfSalt: Uint8Array<ArrayBuffer>,
  createNew = false,
): Promise<{
  credential: PublicKeyCredential;
  rpId: string;
  existing: boolean;
} | null> {
  if (!hasManagedApi() || !(await getManagedAccount())) return null;
  const status = await request('');
  if (!Array.isArray(status.credential_ids))
    throw new Error('Could not check your account passkeys.');
  const existing = !createNew && status.credential_ids.length > 0;
  const operation = existing ? 'use' : 'register';
  const { publicKey, ceremony } = await request(`/${operation}/start`, {});
  const common = {
    ...publicKey,
    challenge: decode(publicKey.challenge),
    extensions: { ...publicKey.extensions, prf: { eval: { first: prfSalt } } },
  };
  let credential: PublicKeyCredential | null;

  if (existing) {
    credential = (await navigator.credentials.get({
      publicKey: {
        ...common,
        allowCredentials: publicKey.allowCredentials.map(
          (c: { id: string; type: string }) => ({ ...c, id: decode(c.id) }),
        ),
      },
    } as CredentialRequestOptions)) as PublicKeyCredential | null;
  } else {
    credential = (await navigator.credentials.create({
      publicKey: {
        ...common,
        user: { ...publicKey.user, id: decode(publicKey.user.id) },
        excludeCredentials: publicKey.excludeCredentials?.map(
          (c: { id: string; type: string }) => ({ ...c, id: decode(c.id) }),
        ),
        authenticatorSelection: {
          ...publicKey.authenticatorSelection,
          residentKey: 'required',
          requireResidentKey: true,
        },
      },
    } as CredentialCreationOptions)) as PublicKeyCredential | null;
  }

  if (!credential) throw new Error('Passkey setup was cancelled.');
  const response = credential.response as AuthenticatorAttestationResponse;
  const payload = existing
    ? authenticationResponse(credential)
    : {
        id: encode(credential.rawId),
        rawId: encode(credential.rawId),
        type: 'public-key',
        response: {
          clientDataJSON: encode(response.clientDataJSON),
          attestationObject: encode(response.attestationObject),
          transports: response.getTransports?.() ?? [],
        },
        clientExtensionResults: {},
      };
  await request(`/${operation}/finish`, payload, ceremony);

  return {
    credential,
    rpId: existing ? publicKey.rpId : publicKey.rp.id,
    existing,
  };
}

/**
 * Sign in to the account with a passkey, from the app: the same ceremony as
 * the portal's "Sign in with passkey", which the account service accepts
 * from the app's origin too. Ends with the shared session cookie set.
 * Resolves false when the person dismissed the prompt.
 */
export async function signInWithAccountPasskey(email = ''): Promise<boolean> {
  const start = await managedFetch('/passkeys/login/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.trim() }),
  });
  if (!start.ok) throw new Error('Could not start passkey sign-in.');
  const { publicKey } = await start.json();

  let credential: PublicKeyCredential | null;

  try {
    credential = (await navigator.credentials.get({
      publicKey: {
        ...publicKey,
        challenge: decode(publicKey.challenge),
        allowCredentials: (publicKey.allowCredentials ?? []).map(
          (c: { id: string; type: string }) => ({ ...c, id: decode(c.id) }),
        ),
      },
    } as CredentialRequestOptions)) as PublicKeyCredential | null;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'NotAllowedError') {
      return false;
    }

    throw error;
  }

  if (!credential) return false;
  const finish = await managedFetch('/passkeys/login/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(authenticationResponse(credential)),
  });

  if (!finish.ok) {
    throw new Error(
      'That passkey is not linked to an account. Use Google or an email link instead.',
    );
  }

  noteManagedSessionChanged();

  return true;
}
