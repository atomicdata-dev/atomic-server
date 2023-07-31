import * as React from 'react';
import {
  useBoolean,
  useNumber,
  useResource,
  useTitle,
  Agent,
  generateKeyPair,
  properties,
} from '@tomic/react';
import { useNavigate, useNavigationType } from 'react-router-dom';

import { ContainerNarrow } from '../components/Containers';
import { ValueForm } from '../components/forms/ValueForm';
import { Button } from '../components/Button';
import { constructOpenURL } from '../helpers/navigation';
import { useSettings } from '../helpers/AppSettings';
import { ResourcePageProps } from './ResourcePage';
import { paths } from '../routes/paths';
import { Row } from '../components/Row';

// Whether Invites should automatically be accepted.
const autoAccept = false;

/** A View that opens an invite */
function InvitePage({ resource }: ResourcePageProps): JSX.Element {
  const [usagesLeft] = useNumber(resource, properties.invite.usagesLeft);
  const [write] = useBoolean(resource, properties.invite.write);
  const navigate = useNavigate();
  const navigationType = useNavigationType();
  const { agent, setAgent } = useSettings();
  const agentResource = useResource(agent?.subject);
  const [agentTitle] = useTitle(agentResource, 15);

  const agentSubject = agent?.subject;

  if (autoAccept && agentSubject && usagesLeft && usagesLeft > 0) {
    // Accept the invite if an agent subject is present, but not if the user just pressed the back button
    if (navigationType !== 'POP') {
      handleAccept(undefined);
    }
  }

  // When the Invite is accepted, a new Agent might be created.
  // When this happens, a new keypair is made, but the subject of the Agent is not yet known.
  // It will be created by the server, and will be accessible in the Redirect response.
  async function handleNew() {
    const keypair = await generateKeyPair();
    const newAgent = new Agent(keypair.privateKey);
    setAgent(newAgent);
    const publicKey = await newAgent.getPublicKey();
    handleAccept(publicKey);
  }

  function handleAccept(publicKey?: string) {
    const inviteURL = new URL(resource.getSubject());

    if (publicKey) {
      inviteURL.searchParams.set('public-key', publicKey);
    } else {
      inviteURL.searchParams.set('agent', agentSubject!);
    }

    // Will be a `Redirect`, see RedirectPage
    navigate(constructOpenURL(inviteURL.href));
  }

  return (
    <ContainerNarrow about={resource.getSubject()}>
      <h1>Invite to {write ? 'edit' : 'view'}</h1>
      <ValueForm resource={resource} propertyURL={properties.description} />
      {usagesLeft === 0 ? (
        <em>Sorry, this Invite has no usages left. Ask for a new one.</em>
      ) : (
        <Row>
          {agentSubject ? (
            <>
              <Button
                data-test='accept-existing'
                onClick={() => handleAccept(undefined)}
              >
                Accept as {agentTitle}
              </Button>
            </>
          ) : (
            <>
              <Button data-test='accept-new' onClick={handleNew}>
                Accept as new user
              </Button>
              <Button
                data-test='accept-sign-in'
                onClick={() => navigate(paths.agentSettings)}
                subtle
              >
                Sign in
              </Button>
            </>
          )}
          {usagesLeft !== undefined && <p>({usagesLeft} usages left)</p>}
        </Row>
      )}
    </ContainerNarrow>
  );
}

export default InvitePage;
