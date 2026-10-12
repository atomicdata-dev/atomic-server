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

/** `?code=` (Phase 6 "Private links") — the invite code for an invite-only
 * form. Server-validated on the definition fetch and consumed at submit; the
 * runtime just rides it along. */
export function getInviteCodeFromLocation(): string | undefined {
  return new URLSearchParams(window.location.search).get('code') ?? undefined;
}

/** The schedule bound a 410 for a not-yet-open / closed form carries
 * alongside its message (see `server/src/handlers/form.rs`). */
interface ErrorBody {
  error?: string;
  /** Epoch-ms of the moment named in `error`. */
  momentMs?: number;
  /** How that moment is spelled inside `error` — the substring to replace. */
  momentUtc?: string;
}

/** Restates a scheduled form's open/close moment in the visitor's own
 * timezone. The server spells it out in UTC because a request carries no
 * timezone, and hands the raw moment over so the browser — which does know —
 * can swap it in. Falls back to the server's UTC wording whenever the pair
 * is missing or `Intl` can't render it. */
export function localizeMoment(
  body: ErrorBody | undefined,
): string | undefined {
  const { error, momentMs, momentUtc } = body ?? {};

  if (!error || momentMs === undefined || !momentUtc) return error;

  try {
    // Explicit components, not `dateStyle`/`timeStyle` — combining either
    // with `timeZoneName` throws, and naming the zone is the whole point.
    const local = new Intl.DateTimeFormat(undefined, {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      timeZoneName: 'short',
    }).format(new Date(momentMs));

    return local ? error.replace(momentUtc, local) : error;
  } catch {
    return error;
  }
}

export async function fetchDefinition(
  id: string,
  code?: string,
): Promise<FormDefinition> {
  const query = code ? `?code=${encodeURIComponent(code)}` : '';
  const res = await fetch(`/form/${id}/definition${query}`);

  if (!res.ok) {
    // Invite-only rejections (403) come with a human-readable reason.
    const body = (await res.json().catch(() => undefined)) as
      | ErrorBody
      | undefined;

    throw new Error(
      localizeMoment(body) ??
        (res.status === 410 || res.status === 404
          ? 'This form is not available.'
          : 'Could not load this form.'),
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
  code?: string,
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
      ...(code ? { code } : {}),
    }),
  });

  if (res.ok) {
    return { ok: true, status: res.status };
  }

  const body = (await res.json().catch(() => undefined)) as
    | (ErrorBody & { errors?: Array<{ field: string; message: string }> })
    | undefined;

  const errors: Record<string, string> = {};

  for (const e of body?.errors ?? []) {
    errors[e.field] = e.message;
  }

  return {
    ok: false,
    status: res.status,
    errors: Object.keys(errors).length > 0 ? errors : undefined,
    message: localizeMoment(body),
  };
}
