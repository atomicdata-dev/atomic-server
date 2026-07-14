import { useId, useState, type FormEvent, type JSX } from 'react';
import type { FormDefinition, FormErrors, FormValues } from './types.js';
import { validatePage, validateAll } from './validation.js';
import { FieldInput } from './FieldInput.js';
import { FormMarkdown } from './FormMarkdown.js';

export type SubmitResult =
  | { ok: true }
  | { ok: false; message?: string; errors?: FormErrors };

export interface FormRendererProps {
  definition: FormDefinition;
  onSubmit: (values: FormValues) => Promise<SubmitResult>;
  /** Disables the honeypot field and turns Submit into a no-op — used by the
   * data-browser builder's preview mode, which renders the same definition
   * JSON but must never write a real submission. */
  preview?: boolean;
  className?: string;
}

type Status = 'filling' | 'submitting' | 'submitted' | 'error';

export function FormRenderer({
  definition,
  onSubmit,
  preview = false,
  className,
}: FormRendererProps): JSX.Element {
  const [pageIndex, setPageIndex] = useState(0);
  const [values, setValues] = useState<FormValues>({});
  const [errors, setErrors] = useState<FormErrors>({});
  const [status, setStatus] = useState<Status>('filling');
  const [serverMessage, setServerMessage] = useState<string | undefined>();
  const [honeypot, setHoneypot] = useState('');
  const groupId = useId();

  const page = definition.pages[pageIndex];
  const isLastPage = pageIndex === definition.pages.length - 1;
  const progress =
    definition.pages.length > 1
      ? Math.round(((pageIndex + 1) / definition.pages.length) * 100)
      : undefined;

  const setValue = (mapsTo: string, value: unknown) => {
    setValues(prev => ({ ...prev, [mapsTo]: value }));
    setErrors(prev => {
      if (!(mapsTo in prev)) return prev;

      const next = { ...prev };
      delete next[mapsTo];

      return next;
    });
  };

  const goNext = () => {
    const result = validatePage(definition, pageIndex, values);

    if (Object.keys(result.errors).length > 0) {
      setErrors(prev => ({ ...prev, ...result.errors }));

      return;
    }

    setPageIndex(i => Math.min(i + 1, definition.pages.length - 1));
  };

  const goBack = () => setPageIndex(i => Math.max(i - 1, 0));

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    if (preview) return;

    const result = validateAll(definition, values);

    if (Object.keys(result.errors).length > 0) {
      setErrors(result.errors);

      // Jump to the first page that has an error so the visitor sees it.
      const firstErrorPage = definition.pages.findIndex(p =>
        p.blocks.some(b => b.kind === 'field' && b.mapsTo in result.errors),
      );

      if (firstErrorPage >= 0) setPageIndex(firstErrorPage);

      return;
    }

    setStatus('submitting');
    // The honeypot's value rides along under its own field key so the host
    // app (form-app) can lift it out to the submit body's top-level `hp`
    // field without FormRenderer needing to know the wire format.
    const outcome = await onSubmit({
      ...result.values,
      [definition.honeypotField]: honeypot,
    });

    if (outcome.ok) {
      setStatus('submitted');
    } else {
      setStatus('error');
      setServerMessage(outcome.message);

      if (outcome.errors) setErrors(outcome.errors);
    }
  };

  if (status === 'submitted') {
    const message =
      (definition.settings.confirmationMessage as string | undefined) ??
      'Thank you, your response has been recorded.';

    return (
      <div className={className}>
        <div className='atomic-form-success' role='status'>
          {message}
        </div>
      </div>
    );
  }

  return (
    <form className={className} onSubmit={handleSubmit} noValidate>
      {progress !== undefined && (
        <div className='atomic-form-progress' aria-hidden='true'>
          <div
            className='atomic-form-progress-bar'
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      <div className='atomic-form-blocks'>
        {page?.blocks.map((block, i) => {
          if (block.kind === 'heading') {
            return (
              <h3 key={i} className='atomic-form-heading'>
                {block.text}
              </h3>
            );
          }

          if (block.kind === 'paragraph') {
            return (
              <FormMarkdown
                key={i}
                className='atomic-form-paragraph'
                text={block.text}
              />
            );
          }

          const inputId = `${groupId}-${block.mapsTo}`;
          // A distinct id from the input's own — `htmlFor` on text-type
          // fields points AT the input, while `aria-labelledby` on
          // radio/multi-select groups (which have no single input to
          // `htmlFor`) points at this label instead. Giving the label the
          // same id as the input it labels would be a duplicate-id
          // collision, breaking the browser's for/id association.
          const labelId = `${inputId}-label`;
          const error = errors[block.mapsTo];
          const showLabel = block.type !== 'checkbox';

          return (
            <div className='atomic-form-field' key={block.mapsTo}>
              {showLabel && (
                <label
                  className='atomic-form-label'
                  htmlFor={inputId}
                  id={labelId}
                >
                  {block.label}
                  {block.required && (
                    <span className='atomic-form-required'>*</span>
                  )}
                </label>
              )}
              {block.description && (
                <FormMarkdown
                  className='atomic-form-description'
                  text={block.description}
                />
              )}
              <FieldInput
                field={block}
                value={values[block.mapsTo]}
                onChange={v => setValue(block.mapsTo, v)}
                inputId={inputId}
                labelId={labelId}
              />
              {error && (
                <p className='atomic-form-error' role='alert'>
                  {error}
                </p>
              )}
            </div>
          );
        })}
      </div>

      {!preview && (
        <input
          type='text'
          name={definition.honeypotField}
          value={honeypot}
          onChange={e => setHoneypot(e.target.value)}
          tabIndex={-1}
          autoComplete='off'
          aria-hidden='true'
          className='atomic-form-honeypot'
        />
      )}

      {status === 'error' && (
        <p className='atomic-form-error atomic-form-submit-error' role='alert'>
          {serverMessage ??
            'Something went wrong submitting this form. Please try again.'}
        </p>
      )}

      <div className='atomic-form-nav'>
        {pageIndex > 0 && (
          <button
            type='button'
            className='atomic-form-button atomic-form-button-secondary'
            onClick={goBack}
          >
            Back
          </button>
        )}
        {!isLastPage && (
          <button type='button' className='atomic-form-button' onClick={goNext}>
            Next
          </button>
        )}
        {isLastPage && (
          <button
            type='submit'
            className='atomic-form-button'
            disabled={status === 'submitting'}
          >
            {status === 'submitting' ? 'Submitting…' : 'Submit'}
          </button>
        )}
      </div>
    </form>
  );
}
