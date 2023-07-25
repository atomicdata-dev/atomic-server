import * as React from 'react';
import { useState } from 'react';
import { Agent } from '@tomic/react';
import { FaCog, FaEye, FaEyeSlash, FaUser } from 'react-icons/fa';

import { useSettings } from '../helpers/AppSettings';
import {
  InputStyled,
  InputWrapper,
  LabelStyled,
} from '../components/forms/InputStyles';
import { ButtonInput, Button } from '../components/Button';
import { Margin } from '../components/Card';
import Field from '../components/forms/Field';
import { ResourceInline } from '../views/ResourceInline';
import { ContainerNarrow } from '../components/Containers';
import { AtomicLink } from '../components/AtomicLink';
import { editURL } from '../helpers/navigation';
import { useNavigate } from 'react-router';
import { ErrorLook } from '../components/ErrorLook';

const SettingsAgent: React.FunctionComponent = () => {
  const { agent, setAgent } = useSettings();
  const [subject, setSubject] = useState<string | undefined>(undefined);
  const [privateKey, setPrivateKey] = useState<string | undefined>(undefined);
  const [error, setError] = useState<Error | undefined>(undefined);
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [secret, setSecret] = useState<string | undefined>(undefined);
  const navigate = useNavigate();

  // When there is an agent, set the advanced values
  // Otherwise, reset the secret value
  React.useEffect(() => {
    if (agent !== undefined) {
      fillAdvanced();
    } else {
      setSecret('');
    }
  }, [agent]);

  // When the key or subject changes, update the secret
  React.useEffect(() => {
    renewSecret();
  }, [subject, privateKey]);

  function renewSecret() {
    if (agent) {
      setSecret(agent.buildSecret());
    }
  }

  function fillAdvanced() {
    try {
      if (!agent) {
        throw new Error('No agent set');
      }

      setSubject(agent.subject);
      setPrivateKey(agent.privateKey);
    } catch (e) {
      const err = new Error('Cannot fill subject and privatekey fields.' + e);
      setError(err);
      setSubject('');
    }
  }

  function handleSignOut() {
    if (
      window.confirm(
        "If you sign out, your secret will be removed. If you haven't saved your secret somewhere, you will lose access to this User. Are you sure you want to sign out?",
      )
    ) {
      setAgent(undefined);
      setError(undefined);
      setSubject('');
      setPrivateKey('');
    }
  }

  function setAgentIfChanged(oldAgent: Agent | undefined, newAgent: Agent) {
    if (JSON.stringify(oldAgent) !== JSON.stringify(newAgent)) {
      setAgent(newAgent);
    }
  }

  /** Called when the secret or the subject is updated manually */
  async function handleUpdateSubjectAndKey() {
    renewSecret();
    setError(undefined);

    try {
      const newAgent = new Agent(privateKey!, subject);
      await newAgent.getPublicKey();
      await newAgent.verifyPublicKeyWithServer();

      setAgentIfChanged(agent, newAgent);
    } catch (e) {
      const err = new Error('Invalid Agent' + e);
      setError(err);
    }
  }

  function handleCopy() {
    secret && navigator.clipboard.writeText(secret);
  }

  /** When the Secret updates, parse it and try if the */
  async function handleUpdateSecret(updateSecret: string) {
    setSecret(updateSecret);

    if (updateSecret === '') {
      setSecret('');
      setError(undefined);

      return;
    }

    setError(undefined);

    try {
      const newAgent = Agent.fromSecret(updateSecret);
      setAgentIfChanged(agent, newAgent);
      setPrivateKey(newAgent.privateKey);
      setSubject(newAgent.subject);
      // This will fail and throw if the agent is not public, which is by default
      // await newAgent.checkPublicKey();
    } catch (e) {
      const err = new Error('Invalid secret. ' + e);
      setError(err);
    }
  }

  return (
    <ContainerNarrow>
      <form>
        <h1>User Settings</h1>
        <p>
          An Agent is a user, consisting of a Subject (its URL) and Private Key.
          Together, these can be used to edit data and sign Commits.
        </p>
        {agent ? (
          <>
            {agent.subject?.startsWith('http://localhost') && (
              <p>
                <ErrorLook>Warning:</ErrorLook>
                {
                  "You're using a local Agent, which cannot authenticate on other domains, because its URL does not resolve."
                }
              </p>
            )}
            <LabelStyled>
              <FaUser /> You{"'"}re signed in as
            </LabelStyled>
            <p>
              <ResourceInline subject={agent.subject!} />
            </p>
            <Button onClick={() => navigate(editURL(agent.subject!))}>
              Edit profile
            </Button>
            <Margin />
          </>
        ) : (
          <p>
            You can create your own Agent by hosting an{' '}
            <AtomicLink href='https://github.com/atomicdata-dev/atomic-data-rust/tree/master/server'>
              atomic-server
            </AtomicLink>
            . Alternatively, you can use{' '}
            <AtomicLink subject='https://atomicdata.dev/invites'>
              an Invite
            </AtomicLink>{' '}
            to get a guest Agent on someone else{"'s"} Atomic Server.
          </p>
        )}
        <Field
          label={agent ? 'Agent Secret' : 'Enter your Agent Secret'}
          helper={
            "The Agent Secret is a long string of characters that encodes both the Subject and the Private Key. You can think of it as a combined username + password. Store it safely, and don't share it with others."
          }
          error={error}
        >
          <InputWrapper>
            <InputStyled
              value={secret}
              onChange={e => handleUpdateSecret(e.target.value)}
              type={showPrivateKey ? 'text' : 'password'}
              disabled={agent !== undefined}
              name='secret'
              id='current-password'
              autoComplete='current-password'
              spellCheck='false'
            />
            <ButtonInput
              type='button'
              title={showPrivateKey ? 'Hide secret' : 'Show secret'}
              onClick={() => setShowPrivateKey(!showPrivateKey)}
            >
              {showPrivateKey ? <FaEyeSlash /> : <FaEye />}
            </ButtonInput>
            <ButtonInput
              type='button'
              title={advanced ? 'Hide advanced' : 'Show advanced'}
              onClick={() => setAdvanced(!advanced)}
            >
              <FaCog />
            </ButtonInput>
            {agent && (
              <ButtonInput type='button' onClick={handleCopy}>
                copy
              </ButtonInput>
            )}
          </InputWrapper>
        </Field>
        {advanced ? (
          <React.Fragment>
            <Field
              label='Subject URL'
              helper={
                'The link to your Agent, e.g. https://atomicdata.dev/agents/someAgent'
              }
            >
              <InputWrapper>
                <InputStyled
                  disabled={agent !== undefined}
                  value={subject}
                  onChange={e => {
                    setSubject(e.target.value);
                    handleUpdateSubjectAndKey();
                  }}
                />
              </InputWrapper>
            </Field>
            <Field
              label='Private Key'
              helper={
                'The private key of the Agent, which is a Base64 encoded string.'
              }
            >
              <InputWrapper>
                <InputStyled
                  disabled={agent !== undefined}
                  type={showPrivateKey ? 'text' : 'password'}
                  value={privateKey}
                  onChange={e => {
                    setPrivateKey(e.target.value);
                    handleUpdateSubjectAndKey();
                  }}
                />
                <ButtonInput
                  type='button'
                  title={
                    showPrivateKey ? 'Hide private key' : 'Show private key'
                  }
                  onClick={() => setShowPrivateKey(!showPrivateKey)}
                >
                  {showPrivateKey ? <FaEyeSlash /> : <FaEye />}
                </ButtonInput>
              </InputWrapper>
            </Field>
          </React.Fragment>
        ) : null}
        {agent && (
          <Button
            subtle
            title='Sign out with current Agent and reset this form'
            onClick={handleSignOut}
            data-test='sign-out'
          >
            sign out
          </Button>
        )}
      </form>
    </ContainerNarrow>
  );
};

export default SettingsAgent;
