import {
  CAPTCHA_VALUE_KEY,
  type FormDefinition,
  type FormValues,
} from '@tomic/form-renderer';

/** The form id is the last path segment of `/form/:id`. Reading it from the
 * URL (rather than threading it through props from the server) keeps this
 * app working unchanged whether it's server-embedded or opened directly
 * against a dev server. */
export function getFormIdFromLocation(): string {
  const segments = window.location.pathname.split('/').filter(Boolean);
  const idx = segments.indexOf('form');

  return idx >= 0 && segments[idx + 1] ? segments[idx + 1] : '';
}

/** `?embed=1` (Phase 6 "Embedding") — read directly from the URL rather than
 * threaded in by the server, so the runtime behaves the same whether the
 * HTML shell is server-rendered or opened straight against a dev server. */
export function isEmbedMode(): boolean {
  return new URLSearchParams(window.location.search).get('embed') === '1';
}

export async function fetchDefinition(id: string): Promise<FormDefinition> {
  const res = await fetch(`/form/${id}/definition`);

  if (!res.ok) {
    throw new Error(
      res.status === 410 || res.status === 404
        ? 'This form is not available.'
        : 'Could not load this form.',
    );
  }

  return (await res.json()) as FormDefinition;
}

export interface SubmitOutcome {
  ok: boolean;
  status: number;
  errors?: Record<string, string>;
  message?: string;
}

export async function submitForm(
  id: string,
  honeypotField: string,
  values: FormValues,
): Promise<SubmitOutcome> {
  // FormRenderer rides the honeypot's and captcha's values along under
  // their own field keys (see FormRenderer.tsx's handleSubmit) — lift them
  // back out to the top-level `hp` / `altcha` fields the server expects,
  // rather than nesting them under `values`.
  const {
    [honeypotField]: honeypotValue,
    [CAPTCHA_VALUE_KEY]: captchaValue,
    ...fieldValues
  } = values;

  const res = await fetch(`/form/${id}/submit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      values: fieldValues,
      [honeypotField]: honeypotValue ?? '',
      altcha: typeof captchaValue === 'string' ? captchaValue : '',
    }),
  });

  if (res.ok) {
    return { ok: true, status: res.status };
  }

  const body = (await res.json().catch(() => undefined)) as
    | { error?: string; errors?: Array<{ field: string; message: string }> }
    | undefined;

  const errors: Record<string, string> = {};

  for (const e of body?.errors ?? []) {
    errors[e.field] = e.message;
  }

  return {
    ok: false,
    status: res.status,
    errors: Object.keys(errors).length > 0 ? errors : undefined,
    message: body?.error,
  };
}
