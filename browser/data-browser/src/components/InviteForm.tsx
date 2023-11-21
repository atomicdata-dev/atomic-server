import {
  useResource,
  useStore,
  properties,
  Resource,
  urls,
  useCurrentAgent,
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
    await invite.set(properties.isA, [urls.classes.invite], store);
    await invite.set(properties.read, [urls.instances.publicAgent], store);
    await invite.set(properties.invite.target, target.getSubject(), store);

    try {
      if (!agent) {
        throw new Error('No agent found');
      }

      await invite.set(properties.parent, agent.subject, store);
      await invite.save(store);
      await navigator.clipboard.writeText(invite.getSubject());
      toast.success('Copied to clipboard');
      setSaved(true);
    } catch (e) {
      setErr(e);
    }
  }, [invite, store, agent, target]);

  if (!saved) {
    return (
      <Card>
        <ResourceField
          label={'Give edit rights'}
          propertyURL={urls.properties.invite.write}
          resource={invite}
        />
        <ResourceField
          label={'Invite text (optional)'}
          propertyURL={urls.properties.description}
          resource={invite}
        />
        <ResourceField
          label={'How many times this link can be used. No value = no limit.'}
          propertyURL={urls.properties.invite.usagesLeft}
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
        <CodeBlock content={invite.getSubject()} data-test='invite-code' />
      </Card>
    );
}
