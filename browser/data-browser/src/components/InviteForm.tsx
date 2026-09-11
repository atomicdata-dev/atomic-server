import { TeamProfileStep } from './TeamProfileStep';
import {
  useResource,
  useBoolean,
  useStore,
  Resource,
  urls,
  useCurrentAgent,
  core,
  server,
  dataBrowser,
} from '@tomic/react';
import { generateInviteToken } from '@tomic/lib';
import { useCallback, useState, type ReactNode } from 'react';
import { Dialog } from './Dialog';
import { managedFetch } from '../helpers/managed/api';
import {
  automaticPeerRoom,
  defaultPeerSignalingUrl,
  savePeerLink,
  resumePeerLinks,
} from '../helpers/browserPeerSync';
import { getManagedPortalUrl } from '../helpers/managed/cloudSync';
import toast from 'react-hot-toast';
import { ErrorLook } from './ErrorLook';
import { Button } from './Button';
import { Column, Row } from './Row';
import { CodeBlock } from './CodeBlock';
import ResourceField from './forms/ResourceField';

interface InviteFormProps {
  /** The resource that becomes accessible on opening the invite */
  target: Resource;
  inDialog?: boolean;
}

/**
 * Allows the user to create a new Invite for some resource. Outputs the
 * generated Subject after saving.
 */
export function InviteForm({ target, inDialog }: InviteFormProps) {
  const [agent] = useCurrentAgent();
  const profile = useResource(agent?.subject);

  if (agent?.subject && profile.error) {
    return <ErrorLook>{profile.error.message}</ErrorLook>;
  }

  if (agent?.subject && !profile.isReady()) return null;

  return (
    <InviteFormContent
      key={agent?.subject}
      target={target}
      inDialog={inDialog}
      skipProfile={!!profile.get(dataBrowser.properties.icon)}
    />
  );
}

function InviteFormContent({
  target,
  skipProfile,
  inDialog,
}: InviteFormProps & { skipProfile: boolean }) {
  const store = useStore();
  const [subject] = useState(() => store.createSubject());
  const invite = useResource(subject, {
    newResource: true,
  });
  const [allowEdits] = useBoolean(invite, server.properties.write);
  const isSaas = !!getManagedPortalUrl();
  const [err, setErr] = useState<Error | undefined>(undefined);
  const [agent] = useCurrentAgent();
  const [profileReviewed, setProfileReviewed] = useState(skipProfile);
  const [saved, setSaved] = useState(false);
  const [inviteUrl, setInviteUrl] = useState<string | undefined>(undefined);

  /** Generates the signed token and constructs the invite URL */
  const createInvite = useCallback(async () => {
    try {
      if (!agent) {
        throw new Error('No agent found');
      }

      const write = (await invite.get(server.properties.write)) as boolean;
      const expiresAt = (await invite.get(
        urls.properties.invite.expiresAt,
      )) as number;

      const isDrive = target.hasClasses(server.classes.drive);
      let browserPeer = isDrive && store.isLocalOnlyDrive(target.subject);

      if (isDrive && isSaas && !browserPeer) {
        const response = await managedFetch('/sync-enrollments', {});
        if (!response.ok || response.status === 204)
          throw new Error(
            'Sign in to your portal account to check this drive before sharing.',
          );
        const body = await response.json();
        const enrollments = Array.isArray(body) ? body : body.enrollments;
        if (!Array.isArray(enrollments))
          throw new Error('Could not check Cloud Server status. Try again.');
        browserPeer = !enrollments.some(
          e => e.drive_subject === target.subject && e.status !== 'Disabled',
        );
      }

      if (browserPeer && !store.isLocalOnlyDrive(target.subject)) {
        throw new Error(
          'This drive still uses a data server. A complete local copy must be verified before switching it to browser-only sharing. Its existing server connection has been kept.',
        );
      }

      if (
        browserPeer &&
        !(await store.getClientDb()?.getResourceWithSnapshot(target.subject))
          ?.snapshot
      )
        throw new Error(
          'Wait for this drive to be saved on this device before sharing.',
        );
      const tokenBase64 = await generateInviteToken(
        target.subject,
        agent,
        !!write,
        expiresAt,
        invite.get(core.properties.description) as string | undefined,
        browserPeer,
      );

      if (browserPeer) {
        savePeerLink(store, {
          drive: target.subject,
          room: await automaticPeerRoom(target.subject),
          signalingUrl: defaultPeerSignalingUrl(),
        });
        resumePeerLinks(store);
      }

      const baseUrl = browserPeer
        ? window.location.origin
        : store.getServerUrl();
      const finalUrl = `${baseUrl}/app/invite?token=${encodeURIComponent(
        tokenBase64,
      )}`;

      setInviteUrl(finalUrl);
      setSaved(true);
      navigator.clipboard.writeText(finalUrl);
      toast.success('Copied to clipboard');
    } catch (e) {
      setErr(e);
    }
  }, [invite, agent, target, store, isSaas]);

  if (agent?.subject && !profileReviewed) {
    return (
      <InviteFormLayout inDialog={inDialog}>
        <TeamProfileStep
          subject={agent.subject}
          onContinue={() => setProfileReviewed(true)}
        />
      </InviteFormLayout>
    );
  }

  if (agent?.subject && !profileReviewed) {
    return (
      <InviteFormLayout inDialog={inDialog}>
        <TeamProfileStep
          subject={agent.subject}
          onContinue={() => setProfileReviewed(true)}
        />
      </InviteFormLayout>
    );
  }

  if (!saved) {
    return (
      <InviteFormLayout
        inDialog={inDialog}
        actions={<Button onClick={createInvite}>Create</Button>}
      >
        <Column gap='1rem'>
          <ResourceField
            label={'Allow edits'}
            propertyURL={server.properties.write}
            resource={invite}
          />
          {isSaas && (
            <p>
              {allowEdits
                ? 'Cloud Server: each editor uses one seat on this drive. An existing editor on this drive counts once. Viewers are free.'
                : 'Browser collaboration is free. Editor seats apply only when this drive uses Cloud Server.'}
            </p>
          )}
          <ResourceField
            label={'Invite text (optional)'}
            propertyURL={core.properties.description}
            resource={invite}
          />
          {err && (
            <p>
              <ErrorLook>{err.message}</ErrorLook>
            </p>
          )}
        </Column>
      </InviteFormLayout>
    );
  } else
    return (
      <InviteFormLayout inDialog={inDialog}>
        <p>Invite created and copied to clipboard! 🚀</p>
        <CodeBlock content={inviteUrl!} data-test='invite-code' />
      </InviteFormLayout>
    );
}

function InviteFormLayout({
  inDialog,
  children,
  actions,
}: {
  inDialog?: boolean;
  children: ReactNode;
  actions?: ReactNode;
}) {
  if (inDialog) {
    return (
      <>
        <Dialog.Content>{children}</Dialog.Content>
        {actions && <Dialog.Actions>{actions}</Dialog.Actions>}
      </>
    );
  }

  return (
    <Column gap='1rem'>
      {children}
      {actions && <Row>{actions}</Row>}
    </Column>
  );
}
