import { Agent } from '@tomic/lib';
import { managedFetch } from './api';
import {
  decryptEnvelopeV2,
  decryptEnvelopeWithAssisted,
  decryptEnvelopeWithPasskey,
  decryptRecoverySecret,
  envelopeWrapperKinds,
  hasAssistedWrapper,
  sameAgent,
  type RecoverySecret,
} from './recovery';
import {
  isValidAppKey,
  sealIdentity,
  type SealedIdentity,
} from './identityHandback';

/**
 * Handing the identity to an app that started a device link with an `app_key`
 * (planning/flutter-secret-handback.md). The page is `/app/send-identity`.
 */

export type LinkDescription = {
  deviceName: string;
  alreadyApproved: boolean;
  /** Null for a link that did not ask for the identity. */
  appKey: string | null;
};

export class NoLinkError extends Error {}

/** What the provider says about a code. Needs the account's cookie session. */
export async function describeLink(code: string): Promise<LinkDescription> {
  const response = await managedFetch(
    `/device-link/code/${encodeURIComponent(code)}`,
  );

  if (response.status === 404) {
    throw new NoLinkError(
      'That code is not valid any more. Ask the device for a new one.',
    );
  }

  if (!response.ok) throw new Error('Could not look up that code.');

  const body = (await response.json()) as {
    device_name?: string;
    already_approved?: boolean;
    app_key?: string | null;
  };

  return {
    deviceName: body.device_name?.trim() || 'a device',
    alreadyApproved: !!body.already_approved,
    appKey: isValidAppKey(body.app_key) ? body.app_key : null,
  };
}

/** Store the sealed identity with the link. The provider approves it too. */
export async function depositSealedIdentity(
  code: string,
  sealed: SealedIdentity,
): Promise<void> {
  const response = await managedFetch(
    `/device-link/code/${encodeURIComponent(code)}/identity`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(sealed),
    },
  );

  if (response.status === 409) {
    throw new Error(
      'This code was already used. Ask the device for a new one.',
    );
  }

  if (!response.ok) throw new Error('Could not send your identity.');
}

export type UnlockMethod = 'assisted' | 'passkey' | 'code' | 'password';

/**
 * The ways this backup opens, best first. Assisted needs the account that owns
 * the backup to be the one signed in; a v1 backup only knows its password.
 */
export function unlockMethods(
  recovery: RecoverySecret,
  accountEmail: string | undefined,
): UnlockMethod[] {
  if (recovery.format_version < 2) return ['password'];

  const { hasPasskey, hasCode } = envelopeWrapperKinds(recovery);
  const methods: UnlockMethod[] = [];

  if (hasAssistedWrapper(recovery) && accountEmail === recovery.owner_email) {
    methods.push('assisted');
  }

  if (hasPasskey) methods.push('passkey');

  if (hasCode) methods.push('code');

  return methods;
}

/** Open the backup. Passkey and code unlocks also add the assisted wrapper. */
export async function unlockBackup(
  recovery: RecoverySecret,
  method: UnlockMethod,
  input = '',
): Promise<string> {
  const secret =
    method === 'assisted'
      ? await decryptEnvelopeWithAssisted(recovery)
      : method === 'passkey'
        ? await decryptEnvelopeWithPasskey(recovery)
        : method === 'code'
          ? await decryptEnvelopeV2(recovery, input.trim())
          : await decryptRecoverySecret(recovery, input.trim());

  await assertSecretIsBackupAgent(secret, recovery.agent_subject);

  return secret;
}

/** The unlocked agent has to be the one the backup says it holds. */
export async function assertSecretIsBackupAgent(
  secret: string,
  backupSubject: string,
): Promise<void> {
  const agent = await Agent.fromSecret(secret);

  if (!agent.subject || !sameAgent(agent.subject, backupSubject)) {
    throw new Error('This backup holds a different identity than expected.');
  }
}

/** Unlock, seal to the app's key and deposit. */
export async function sendIdentity(
  code: string,
  link: LinkDescription,
  recovery: RecoverySecret,
  secret: string,
): Promise<void> {
  if (!link.appKey)
    throw new Error('This device did not ask for your identity.');

  const sealed = await sealIdentity(link.appKey, {
    secret,
    subject: recovery.agent_subject,
    drive: recovery.drive_subject ?? null,
  });

  await depositSealedIdentity(code, sealed);
}
