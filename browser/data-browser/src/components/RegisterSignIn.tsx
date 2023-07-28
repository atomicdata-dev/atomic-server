import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useDialog,
} from './Dialog';
import React, { FormEvent, useCallback, useEffect, useState } from 'react';
import { useSettings } from '../helpers/AppSettings';
import { Button } from './Button';
import {
  addPublicKey,
  nameRegex,
  register as createRegistration,
  useServerSupports,
  useServerURL,
  useStore,
} from '@tomic/react';
import Field from './forms/Field';
import { InputWrapper, InputStyled } from './forms/InputStyles';
import { Row } from './Row';
import { ErrorLook } from './ErrorLook';
import { SettingsAgent } from './SettingsAgent';

interface RegisterSignInProps {
  // URL where to send the user to after successful registration
  redirect?: string;
}

/** What is currently showing */
enum PageStateOpts {
  none,
  signIn,
  register,
  reset,
  mailSentRegistration,
  mailSentAddPubkey,
}

/**
 * Two buttons: Register / Sign in.
 * Opens a Dialog / Modal with the appropriate form.
 */
export function RegisterSignIn({
  children,
}: React.PropsWithChildren<RegisterSignInProps>): JSX.Element {
  const { dialogProps, show, close } = useDialog();
  const { agent } = useSettings();
  const [pageState, setPageState] = useState<PageStateOpts>(PageStateOpts.none);
  const [email, setEmail] = useState('');
  const { emailRegister } = useServerSupports();

  if (agent) {
    return <>{children}</>;
  } else if (!emailRegister) {
    return (
      <>
        <SettingsAgent />
        <ErrorLook>No e-mail support on this server...</ErrorLook>
      </>
    );
  }

  return (
    <>
      <Row>
        <Button
          onClick={() => {
            setPageState(PageStateOpts.register);
            show();
          }}
        >
          Register
        </Button>
        <Button
          subtle
          onClick={() => {
            setPageState(PageStateOpts.signIn);
            show();
          }}
        >
          Sign In
        </Button>
      </Row>
      <Dialog {...dialogProps}>
        {pageState === PageStateOpts.register && (
          <Register
            setPageState={setPageState}
            email={email}
            setEmail={setEmail}
          />
        )}
        {pageState === PageStateOpts.signIn && (
          <SignIn setPageState={setPageState} />
        )}
        {pageState === PageStateOpts.reset && (
          <Reset
            email={email}
            setEmail={setEmail}
            setPageState={setPageState}
          />
        )}
        {pageState === PageStateOpts.mailSentRegistration && (
          <MailSentConfirm
            email={email}
            close={close}
            message={'Your account will be created when you open that link.'}
          />
        )}
        {pageState === PageStateOpts.mailSentAddPubkey && (
          <MailSentConfirm
            email={email}
            close={close}
            message={'Click that link to create a new PassPhrase.'}
          />
        )}
      </Dialog>
    </>
  );
}

function Reset({ email, setEmail, setPageState }) {
  const store = useStore();
  const [err, setErr] = useState<Error | undefined>(undefined);

  const handleRequestReset = useCallback(async () => {
    try {
      await addPublicKey(store, email);
      setPageState(PageStateOpts.mailSentAddPubkey);
    } catch (e) {
      setErr(e);
    }
  }, [email]);

  return (
    <>
      <DialogTitle>
        <h1>Reset your PassKey</h1>
      </DialogTitle>
      <DialogContent>
        <p>
          {
            "Lost it? No worries, we'll send a link that let's you create a new one."
          }
        </p>
        <EmailField
          email={email}
          setEmail={(e: any) => {
            setErr(undefined);
            setEmail(e);
          }}
        />
        {err && <ErrorLook>{err.message}</ErrorLook>}
      </DialogContent>
      <DialogActions>
        <Button onClick={handleRequestReset}>Send me</Button>
      </DialogActions>
    </>
  );
}

function MailSentConfirm({ email, close, message }) {
  return (
    <>
      <DialogTitle>
        <h1>Go to your email inbox</h1>
      </DialogTitle>
      <DialogContent>
        <p>
          {"We've sent a confirmation link to "}
          <strong>{email}</strong>
          {'.'}
        </p>
        <p>{message}</p>
      </DialogContent>
      <DialogActions>
        <Button onClick={close}>{"Ok, I'll open my mailbox!"}</Button>
      </DialogActions>
    </>
  );
}

function Register({ setPageState, email, setEmail }) {
  const [name, setName] = useState('');
  const [serverUrlStr] = useServerURL();
  const [nameErr, setErr] = useState<Error | undefined>(undefined);
  const store = useStore();

  const serverUrl = new URL(serverUrlStr);
  serverUrl.host = `${name}.${serverUrl.host}`;

  useEffect(() => {
    // check regex of name, set error
    if (!name.match(nameRegex)) {
      setErr(new Error('Name must be lowercase and only contain numbers'));
    } else {
      setErr(undefined);
    }
  }, [name, email]);

  const handleSubmit = useCallback(
    async (event: FormEvent) => {
      event.preventDefault();

      if (!name) {
        setErr(new Error('Name is required'));

        return;
      }

      try {
        await createRegistration(store, name, email);
        setPageState(PageStateOpts.mailSentRegistration);
      } catch (er) {
        setErr(er);
      }
    },
    [name, email],
  );

  return (
    <>
      <DialogTitle>
        <h1>Register</h1>
      </DialogTitle>
      <DialogContent>
        <form onSubmit={handleSubmit} id='register-form'>
          <Field
            label='Username (must be unique)'
            helper='Becomes a part of your URL, e.g. `example.atomicdata.dev`'
          >
            <InputWrapper>
              <InputStyled
                autoFocus={true}
                pattern={nameRegex}
                type={'text'}
                required
                value={name}
                onChange={e => {
                  setName(e.target.value);
                }}
              />
            </InputWrapper>
          </Field>
          <EmailField email={email} setEmail={setEmail} />
          {name && nameErr && <ErrorLook>{nameErr.message}</ErrorLook>}
        </form>
      </DialogContent>
      <DialogActions>
        <Button subtle onClick={() => setPageState(PageStateOpts.signIn)}>
          Sign in
        </Button>
        <Button
          type='submit'
          form='register-form'
          disabled={!name || !!nameErr}
          onClick={handleSubmit}
        >
          Save
        </Button>
      </DialogActions>
    </>
  );
}

function SignIn({ setPageState }) {
  return (
    <>
      <DialogTitle>
        <h1>Sign in</h1>
      </DialogTitle>
      <DialogContent>
        <SettingsAgent />
      </DialogContent>
      <DialogActions>
        <Button subtle onClick={() => setPageState(PageStateOpts.register)}>
          Register
        </Button>
        <Button subtle onClick={() => setPageState(PageStateOpts.reset)}>
          I lost my passphrase
        </Button>
      </DialogActions>
    </>
  );
}

function EmailField({ setEmail, email }) {
  return (
    <Field label='E-mail'>
      <InputWrapper>
        <InputStyled
          // This is not properly working atm
          autoFocus
          type={'email'}
          required
          value={email}
          onChange={e => {
            setEmail(e.target.value);
          }}
        />
      </InputWrapper>
    </Field>
  );
}
