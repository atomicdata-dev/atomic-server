import { confirmEmail, useStore } from '@tomic/react';
import * as React from 'react';
import { useState } from 'react';
import toast from 'react-hot-toast';
import { Button } from '../components/Button';
import { CodeBlockStyled } from '../components/CodeBlock';
import { ContainerNarrow } from '../components/Containers';
import { isDev } from '../config';
import { useSettings } from '../helpers/AppSettings';
import {
  useCurrentSubject,
  useSubjectParam,
} from '../helpers/useCurrentSubject';
import { paths } from './paths';

/** Route that connects to `/confirm-email`, which confirms an email and creates a secret key. */
const ConfirmEmail: React.FunctionComponent = () => {
  // Value shown in navbar, after Submitting
  const [subject] = useCurrentSubject();
  const [secret, setSecret] = useState('');
  const store = useStore();
  const [token] = useSubjectParam('token');
  const { setAgent } = useSettings();
  const [destinationToGo, setDestination] = useState<string>();
  const [err, setErr] = useState<Error | undefined>(undefined);
  const [triedConfirm, setTriedConfirm] = useState(false);

  const handleConfirm = React.useCallback(async () => {
    setTriedConfirm(true);
    let tokenUrl = subject as string;

    if (isDev()) {
      const url = new URL(store.getServerUrl());
      url.pathname = paths.confirmEmail;
      url.searchParams.set('token', token as string);
      tokenUrl = url.href;
    }

    try {
      const { agent: newAgent, destination } = await confirmEmail(
        store,
        tokenUrl,
      );
      setSecret(newAgent.buildSecret());
      setDestination(destination);
      setAgent(newAgent);
      toast.success('Email confirmed!');
    } catch (e) {
      setErr(e);
    }
  }, [subject]);

  if (!triedConfirm && subject) {
    handleConfirm();
  }

  if (err) {
    if (err.message.includes('expired')) {
      return (
        <ContainerNarrow>
          The link has expired. Request a new one by Registering again.
        </ContainerNarrow>
      );
    }

    return <ContainerNarrow>{err?.message}</ContainerNarrow>;
  }

  if (secret) {
    return <SavePassphrase secret={secret} destination={destinationToGo} />;
  }

  return <ContainerNarrow>Verifying token...</ContainerNarrow>;
};

function SavePassphrase({ secret, destination }) {
  const [copied, setCopied] = useState(false);

  function copyToClipboard() {
    setCopied(secret);
    navigator.clipboard.writeText(secret || '');
    toast.success('Copied to clipboard');
  }

  return (
    <ContainerNarrow>
      <h1>Mail confirmed, please save your passphrase</h1>
      <p>
        Your Passphrase is like your password. Never share it with anyone. Use a
        password manager like{' '}
        <a href='https://bitwarden.com/' target='_blank' rel='noreferrer'>
          BitWarden
        </a>{' '}
        to store it securely.
      </p>
      <CodeBlockStyled wrapContent>{secret}</CodeBlockStyled>
      {copied ? (
        <a href={destination} target='_blank' rel='noreferrer'>
          {"I've saved my PassPhrase, open my new Drive!"}
        </a>
      ) : (
        <Button onClick={copyToClipboard}>Copy Passphrase</Button>
      )}
    </ContainerNarrow>
  );
}

export default ConfirmEmail;
