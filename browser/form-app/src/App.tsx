import { useEffect, useState, type JSX } from 'react';
import {
  FormRenderer,
  FormShell,
  draftKey,
  type FormDefinition,
} from '@tomic/form-renderer';
import {
  fetchDefinition,
  getFormIdFromLocation,
  getInviteCodeFromLocation,
  isEmbedMode,
  submitForm,
} from './api.js';
import { startEmbedResizeReporting } from './embedResize.js';

export function App(): JSX.Element {
  const [definition, setDefinition] = useState<FormDefinition | undefined>(
    window.__FORM_DEFINITION__,
  );
  const [error, setError] = useState<string | undefined>();
  const [formId] = useState(getFormIdFromLocation);
  const [embed] = useState(isEmbedMode);
  const [inviteCode] = useState(getInviteCodeFromLocation);

  useEffect(() => {
    if (definition) return;

    fetchDefinition(formId, inviteCode)
      .then(setDefinition)
      .catch(e =>
        setError(e instanceof Error ? e.message : 'Could not load this form.'),
      );
  }, [definition, formId, inviteCode]);

  // The custom background lives in a CSS variable FormShell writes as an
  // inline style on the shell, so it cannot cascade up to <html> — and <html>
  // is what paints the canvas, including the scrollbar gutter that
  // `scrollbar-gutter: stable` reserves outside the shell. Mirror it onto the
  // document element so the gutter matches the form instead of staying white.
  useEffect(() => {
    const background = definition?.styling.backgroundColor;

    if (!background) return;

    document.documentElement.style.setProperty('--atomic-form-bg', background);

    return () => {
      document.documentElement.style.removeProperty('--atomic-form-bg');
    };
  }, [definition]);

  useEffect(() => {
    if (!embed) return;

    document.documentElement.classList.add('atomic-form-embed');

    return startEmbedResizeReporting();
  }, [embed]);

  if (error) {
    return (
      <main className='atomic-form-app-shell'>
        <p className='atomic-form-app-message'>{error}</p>
      </main>
    );
  }

  if (!definition) {
    return (
      <main className='atomic-form-app-shell'>
        <p className='atomic-form-app-message'>Loading…</p>
      </main>
    );
  }

  return (
    <FormShell definition={definition} embed={embed}>
      <FormRenderer
        definition={definition}
        // Keyed on the publish slug rather than the URL's `:id`, which may be
        // either the slug or the raw DID — one form, one draft either way.
        // The invite code scopes it further: each private link is its own
        // one-time response, so their drafts must not bleed together on a
        // shared device.
        draftKey={draftKey(definition.id, inviteCode)}
        onSubmit={async values => {
          const outcome = await submitForm(
            formId,
            definition.honeypotField,
            values,
            inviteCode,
          );

          if (outcome.ok) return { ok: true };

          return {
            ok: false,
            message:
              outcome.message ??
              (outcome.status === 429
                ? 'Too many submissions, please try again later.'
                : 'Something went wrong submitting this form. Please try again.'),
            errors: outcome.errors,
          };
        }}
      />
    </FormShell>
  );
}
