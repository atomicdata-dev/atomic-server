import {
  useResource,
  useStore,
  Resource,
  urls,
  useCurrentAgent,
  core,
  server,
} from '@tomic/react';
import { useCallback, useState } from 'react';
import toast from 'react-hot-toast';
import { ErrorLook } from './ErrorLook';
import { Button } from './Button';
import { Card } from './Card';
import { CodeBlock } from './CodeBlock';
import ResourceField from './forms/ResourceField';

interface InviteFormProps {
  /** The resource that becomes accessible on opening the invite */
  target: Resource;
}

/**
 * Allows the user to create a new Invite for some resource. Outputs the
 * generated Subject after saving.
 */
export function InviteForm({ target }: InviteFormProps) {
  const store = useStore();
  const [subject] = useState(() => store.createSubject('invite'));
  const invite = useResource(subject, {
    newResource: true,
  });
  const [err, setErr] = useState<Error | undefined>(undefined);
  const [agent] = useCurrentAgent();
  const [saved, setSaved] = useState(false);

  /** Stores the Invite, sends it to the server, shows the Subject to the User */
  const createInvite = useCallback(async () => {
    await invite.set(core.properties.isA, [server.classes.invite]);
    await invite.set(core.properties.read, [urls.instances.publicAgent]);
    await invite.set(server.properties.target, target.subject);

    try {
      if (!agent) {
        throw new Error('No agent found');
      }

      await invite.set(core.properties.parent, agent.subject);
      await invite.save();
      await navigator.clipboard.writeText(invite.subject);
      toast.success('Copied to clipboard');
      setSaved(true);
    } catch (e) {
      setErr(e);
    }
  }, [invite, agent, target]);

  if (!saved) {
    return (
      <Card>
        <ResourceField
          label={'Give edit rights'}
          propertyURL={server.properties.write}
          resource={invite}
        />
        <ResourceField
          label={'Invite text (optional)'}
          propertyURL={core.properties.description}
          resource={invite}
        />
        <ResourceField
          label={'How many times this link can be used. No value = no limit.'}
          propertyURL={server.properties.usagesLeft}
          resource={invite}
        />
        <Button onClick={createInvite}>Create Invite</Button>
        {err && (
          <p>
            <ErrorLook>{err.message}</ErrorLook>
          </p>
        )}
      </Card>
    );
  } else
    return (
      <Card>
        <p>Invite created and copied to clipboard! Send it to your buddy:</p>
        <CodeBlock content={invite.subject} data-test='invite-code' />
      </Card>
    );
}
