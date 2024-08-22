import { Agent } from '@tomic/react';
import React, { useState } from 'react';
import { FaCog, FaEye, FaEyeSlash } from 'react-icons/fa';
import { useSettings } from '../helpers/AppSettings';
import { ButtonInput } from './Button';
import Field from './forms/Field';
import { InputStyled, InputWrapper } from './forms/InputStyles';

/** Form where users can post their Private Key, or edit their Agent */
export const SettingsAgent: React.FunctionComponent = () => {
  const { agent, setAgent } = useSettings();
  const [subject, setSubject] = useState<string | undefined>(undefined);
  const [privateKey, setPrivateKey] = useState<string | undefined>(undefined);
  const [error, setError] = useState<Error | undefined>(undefined);
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [secret, setSecret] = useState<string | undefined>(undefined);

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
    <form>
      <Field
        label={agent ? 'Passphrase' : 'Enter your Passphrase'}
        helper={
          "The Agent Passphrase is a secret, long string of characters that encodes both the Subject and the Private Key. You can think of it as a combined username + password. Store it safely, and don't share it with others."
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
            placeholder='Paste your Passphrase'
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
                title={showPrivateKey ? 'Hide private key' : 'Show private key'}
                onClick={() => setShowPrivateKey(!showPrivateKey)}
              >
                {showPrivateKey ? <FaEyeSlash /> : <FaEye />}
              </ButtonInput>
            </InputWrapper>
          </Field>
        </React.Fragment>
      ) : null}
    </form>
  );
};
