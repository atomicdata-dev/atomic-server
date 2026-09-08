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

      const tokenBase64 = await generateInviteToken(
        target.subject,
        agent,
        !!write,
        expiresAt,
      );

      const baseUrl = store.getServerUrl();
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
  }, [invite, agent, target, store]);

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
                : 'Viewers are free. Allowing edits requires a team editor seat for Cloud Server.'}
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
