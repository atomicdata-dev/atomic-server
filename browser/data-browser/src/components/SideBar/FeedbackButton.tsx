import { useStore } from '@tomic/react';
import { FeedbackDiagnostics } from './FeedbackDiagnostics';
import {
  currentDiagnosticText,
  type DiagnosticPreview,
} from '../../helpers/diagnostic-report';
import { useId, useRef, useState, type RefObject } from 'react';
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
import Field from '../forms/Field';
import { Column } from '../Row';
import {
  errorFeedbackMessage,
  FEEDBACK_MESSAGE_MAX_LENGTH,
  submitFeedback,
} from '../../helpers/feedback';

interface UseFeedbackDialogOptions {
  /** Prefills the message with details of this error. */
  reportError?: Error;
  /** Receives focus again when the dialog closes. */
  triggerRef?: RefObject<HTMLElement | null>;
}

/**
 * The "Send feedback" dialog. Returns a function that opens it and the dialog
 * element, which the caller renders. Used by {@link FeedbackButton} and by the
 * sidebar account menu.
 */
export function useFeedbackDialog({
  reportError,
  triggerRef,
}: UseFeedbackDialogOptions = {}) {
  const store = useStore();
  const [diagnosticPreview, setDiagnosticPreview] =
    useState<DiagnosticPreview>();
  const feedbackTitle = reportError ? 'Report this error' : 'Send feedback';
  const messageId = useId();
  const emailId = useId();
  const emailRef = useRef<HTMLInputElement>(null);
  const [dialogProps, showDialog, hideDialog] = useDialog({
    triggerRef: triggerRef as RefObject<HTMLElement>,
  });
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
      await submitFeedback(
        message,
        email,
        reportError ? 'error' : 'sidebar',
        currentDiagnosticText(store.diagnostics, diagnosticPreview),
      );
      setDiagnosticPreview(undefined);
      setSent(true);
      setMessage('');
    } catch {
      setFailed(true);
    }

    setBusy(false);
  }

  function open() {
    setSent(false);
    if (reportError) setMessage(errorFeedbackMessage(reportError));
    showDialog();
  }

  const dialog = (
    <Dialog {...dialogProps} hideOnboardingFeedback>
      <DialogTitle>
        <h1>{feedbackTitle}</h1>
      </DialogTitle>
      <DialogContent>
        {sent ? (
          <p role='status'>Thank you. Your feedback has been received.</p>
        ) : (
          <Column>
            <p>
              Report a bug or suggest an improvement. Your message and optional
              email go to the Atomic team through Sentry. Please leave out
              private workspace content.
            </p>
            <Field label='Feedback' fieldId={messageId} disabled={busy}>
              <InputWrapper>
                <TextAreaStyled
                  id={messageId}
                  rows={5}
                  maxLength={FEEDBACK_MESSAGE_MAX_LENGTH}
                  value={message}
                  onChange={event => setMessage(event.target.value)}
                  disabled={busy}
                  style={{ width: '100%', boxSizing: 'border-box' }}
                />
              </InputWrapper>
            </Field>
            {dialogProps.show && (
              <FeedbackDiagnostics
                onSelect={setDiagnosticPreview}
                disabled={busy}
              >
                <Field
                  label='Email for a reply (optional)'
                  fieldId={emailId}
                  disabled={busy}
                >
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
                </Field>
              </FeedbackDiagnostics>
            )}
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
  );

  return { open, dialog };
}

/** A floating "Feedback" button that opens the feedback dialog. */
export function FeedbackButton({ reportError }: { reportError?: Error }) {
  const triggerRef = useRef<HTMLButtonElement>(null);
  const { open, dialog } = useFeedbackDialog({ reportError, triggerRef });

  return (
    <>
      <Button subtle ref={triggerRef} onClick={open}>
        <FaComment aria-hidden />
        {reportError ? 'Report this error' : 'Feedback'}
      </Button>
      {dialog}
    </>
  );
}
