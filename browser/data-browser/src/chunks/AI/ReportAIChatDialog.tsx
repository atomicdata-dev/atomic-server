import { useEffect, useId, useRef, useState } from 'react';
import * as Sentry from '@sentry/react';
import { type Ai, useStore } from '@tomic/react';
import {
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
} from '@components/Dialog';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import {
  InputStyled,
  InputWrapper,
  TextAreaStyled,
} from '@components/forms/InputStyles';
import { submitFeedback } from '@helpers/feedback';
import { loadChatMessages } from './chatConversionUtils';
import {
  formatAIChatReport,
  MAX_AI_CHAT_REPORT_LENGTH,
} from './formatAIChatReport';

/** Only the explicit Send report action transmits the reviewed transcript. */
export default function ReportAIChatDialog({
  subject,
  show,
  onClose,
  onClosed,
}: {
  subject: string;
  show: boolean;
  onClose: () => void;
  onClosed: () => void;
}) {
  const store = useStore();
  const detailsId = useId();
  const transcriptId = useId();
  const emailId = useId();
  const emailRef = useRef<HTMLInputElement>(null);
  const [details, setDetails] = useState('');
  const [transcript, setTranscript] = useState('');
  const [email, setEmail] = useState('');
  const [omittedMessages, setOmittedMessages] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [sending, setSending] = useState(false);
  const [sendFailed, setSendFailed] = useState(false);
  const [sent, setSent] = useState(false);
  const enabled = Sentry.isEnabled();

  useEffect(() => {
    if (!show) return;
    let cancelled = false;
    setLoading(true);
    setLoadFailed(false);

    void (async () => {
      try {
        const chat = await store.getResource<Ai.AiChat>(subject);
        const messages = await loadChatMessages(chat, store);
        const report = formatAIChatReport(
          chat.title,
          Array.from(messages.keys()),
        );

        if (!cancelled) {
          setTranscript(report.text);
          setOmittedMessages(report.omittedMessages);
        }
      } catch {
        if (!cancelled) setLoadFailed(true);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [show, subject, store]);

  async function copy() {
    setCopyFailed(false);
    setCopied(false);

    try {
      await navigator.clipboard.writeText(
        /* @wc-ignore */
        `What went wrong:\n${details.trim() || '(No description)'}\n\n${transcript}`,
      );
      setCopied(true);
    } catch {
      setCopyFailed(true);
    }
  }

  async function send() {
    if (!emailRef.current?.reportValidity()) return;
    setSending(true);
    setSendFailed(false);

    try {
      await submitFeedback(
        /* @wc-ignore */
        `What went wrong:\n${details.trim() || '(No description)'}\n\n${transcript}`,
        email,
        'ai-chat',
      );
      setSent(true);
    } catch {
      setSendFailed(true);
    } finally {
      setSending(false);
    }
  }

  return (
    <Dialog
      show={show}
      onClose={onClose}
      onClosed={onClosed}
      hideOnboardingFeedback
      width='min(42rem, 100%)'
    >
      <DialogTitle>
        <h1>Report AI chat</h1>
      </DialogTitle>
      <DialogContent>
        {sent ? (
          <p role='status'>Thank you. Your AI chat report has been sent.</p>
        ) : (
          <Column>
            <p>
              Pressing Send report shares the reviewed chat text, error
              messages, and your optional description and email with the Atomic
              team through Sentry. Attachments, tool payloads, and reasoning are
              excluded. Remove private information before sending.
            </p>
            {loading ? (
              <p role='status'>Preparing chat transcript…</p>
            ) : loadFailed ? (
              <p role='alert'>The chat could not be loaded. Try again.</p>
            ) : (
              <>
                <label htmlFor={detailsId}>
                  What went wrong?
                  <InputWrapper>
                    <TextAreaStyled
                      id={detailsId}
                      rows={3}
                      maxLength={2000}
                      value={details}
                      onChange={event => setDetails(event.target.value)}
                      disabled={sending}
                      style={{ width: '100%', boxSizing: 'border-box' }}
                    />
                  </InputWrapper>
                </label>
                <label htmlFor={transcriptId}>
                  Chat transcript (editable)
                  <InputWrapper>
                    <TextAreaStyled
                      id={transcriptId}
                      rows={12}
                      maxLength={MAX_AI_CHAT_REPORT_LENGTH}
                      value={transcript}
                      onChange={event => setTranscript(event.target.value)}
                      disabled={sending}
                      style={{ width: '100%', boxSizing: 'border-box' }}
                    />
                  </InputWrapper>
                </label>
                {omittedMessages > 0 && (
                  <p role='status'>
                    {omittedMessages} earlier messages were omitted to fit the
                    report. The most recent messages are included.
                  </p>
                )}
                <label htmlFor={emailId}>
                  Email for a reply (optional)
                  <InputWrapper>
                    <InputStyled
                      id={emailId}
                      type='email'
                      ref={emailRef}
                      value={email}
                      onChange={event => setEmail(event.target.value)}
                      disabled={sending}
                    />
                  </InputWrapper>
                </label>
                {!enabled && (
                  <p role='status'>
                    Feedback reporting is unavailable on this installation. You
                    can copy the report instead.
                  </p>
                )}
                {copied && <p role='status'>Report copied to clipboard.</p>}
                {copyFailed && (
                  <p role='alert'>
                    Could not copy. Select the text above to copy it manually.
                  </p>
                )}
                {sendFailed && (
                  <p role='alert'>
                    The report could not be sent. Your text is still here; try
                    again.
                  </p>
                )}
              </>
            )}
          </Column>
        )}
      </DialogContent>
      <DialogActions>
        <Button subtle onClick={onClose} disabled={sending}>
          Close
        </Button>
        {!sent && (
          <>
            <Button
              subtle
              onClick={() => void copy()}
              disabled={loading || loadFailed || !transcript.trim() || sending}
            >
              Copy report
            </Button>
            <Button
              onClick={() => void send()}
              disabled={
                loading ||
                loadFailed ||
                !enabled ||
                !transcript.trim() ||
                sending
              }
              loading={sending ? 'Sending report' : undefined}
            >
              Send report
            </Button>
          </>
        )}
      </DialogActions>
    </Dialog>
  );
}
