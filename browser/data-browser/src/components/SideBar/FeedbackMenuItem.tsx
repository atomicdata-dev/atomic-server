import { useId, useRef, useState } from 'react';
import { FaComment } from 'react-icons/fa6';
import * as Sentry from '@sentry/react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  useDialog,
} from '../Dialog';
import {
  InputStyled,
  InputWrapper,
  TextAreaStyled,
} from '../forms/InputStyles';
import { Button } from '../Button';
import { Column } from '../Row';
import {
  SideBarMenuRow,
  SideBarMenuRowIcon,
  SideBarMenuRowLabel,
} from './SideBarMenuItem';
import { submitFeedback } from '../../helpers/feedback';

export function FeedbackMenuItem() {
  const messageId = useId();
  const emailId = useId();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const emailRef = useRef<HTMLInputElement>(null);
  const [dialogProps, showDialog, hideDialog] = useDialog({ triggerRef });
  const [message, setMessage] = useState('');
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [sent, setSent] = useState(false);
  const enabled = Sentry.isEnabled();

  async function send() {
    if (!emailRef.current?.reportValidity()) return;
    setBusy(true);
    setFailed(false);

    try {
      await submitFeedback(message, email);
      setSent(true);
      setMessage('');
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <SideBarMenuRow
        as='button'
        ref={triggerRef}
        type='button'
        onClick={() => {
          setSent(false);
          showDialog();
        }}
        style={{
          border: 0,
          background: 'transparent',
          font: 'inherit',
          cursor: 'pointer',
        }}
      >
        <SideBarMenuRowIcon>
          <FaComment />
        </SideBarMenuRowIcon>
        <SideBarMenuRowLabel>Feedback</SideBarMenuRowLabel>
      </SideBarMenuRow>
      <Dialog {...dialogProps}>
        <DialogTitle>
          <h1>Send feedback</h1>
        </DialogTitle>
        <DialogContent>
          {sent ? (
            <p role='status'>Thank you. Your feedback has been received.</p>
          ) : (
            <Column>
              <p>
                Report a bug or suggest an improvement. Your message and
                optional email go to the Atomic team through Sentry. Please
                leave out private workspace content.
              </p>
              <label htmlFor={messageId}>
                Feedback
                <InputWrapper>
                  <TextAreaStyled
                    id={messageId}
                    rows={5}
                    maxLength={10000}
                    value={message}
                    onChange={event => setMessage(event.target.value)}
                    disabled={busy}
                    style={{ width: '100%', boxSizing: 'border-box' }}
                  />
                </InputWrapper>
              </label>
              <label htmlFor={emailId}>
                Email for a reply (optional)
                <InputWrapper>
                  <InputStyled
                    id={emailId}
                    type='email'
                    ref={emailRef}
                    value={email}
                    onChange={event => setEmail(event.target.value)}
                    disabled={busy}
                  />
                </InputWrapper>
              </label>
              {!enabled && (
                <p role='status'>
                  Feedback reporting is unavailable on this installation. Email{' '}
                  <a href='mailto:info@ontola.io'>
                    {/* @wc-ignore */ 'info@ontola.io'}
                  </a>
                  .
                </p>
              )}
              {failed && (
                <p role='alert'>
                  Feedback could not be sent. Your text is still here. Try again
                  or email{' '}
                  <a href='mailto:info@ontola.io'>
                    {/* @wc-ignore */ 'info@ontola.io'}
                  </a>
                  .
                </p>
              )}
            </Column>
          )}
        </DialogContent>
        <DialogActions>
          <Button subtle onClick={() => hideDialog(false)} disabled={busy}>
            Close
          </Button>
          {!sent && (
            <Button
              onClick={send}
              disabled={!enabled || !message.trim() || busy}
              loading={busy ? 'Sending feedback' : undefined}
            >
              Send feedback
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </>
  );
}
