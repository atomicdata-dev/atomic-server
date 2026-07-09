import { useEffect, useState, type JSX } from 'react';
import { FormRenderer, type FormDefinition } from '@tomic/form-renderer';
import { fetchDefinition, getFormIdFromLocation, submitForm } from './api.js';

export function App(): JSX.Element {
  const [definition, setDefinition] = useState<FormDefinition | undefined>(
    window.__FORM_DEFINITION__,
  );
  const [error, setError] = useState<string | undefined>();
  const [formId] = useState(getFormIdFromLocation);

  useEffect(() => {
    if (definition) return;

    fetchDefinition(formId)
      .then(setDefinition)
      .catch(e =>
        setError(e instanceof Error ? e.message : 'Could not load this form.'),
      );
  }, [definition, formId]);

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
    <main className='atomic-form-app-shell'>
      <div className='atomic-form-app-card'>
        <h1 className='atomic-form-app-title'>{definition.name}</h1>
        <FormRenderer
          definition={definition}
          onSubmit={async values => {
            const outcome = await submitForm(
              formId,
              definition.honeypotField,
              values,
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
      </div>
    </main>
  );
}
