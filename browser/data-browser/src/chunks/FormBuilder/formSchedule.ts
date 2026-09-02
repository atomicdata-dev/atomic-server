/**
 * Publish state + scheduling window, mirroring
 * `server/src/forms.rs::form_availability_at` — the server is authoritative
 * (it gates `/form/:id`, `/definition` and `/submit`), this is the builder's
 * copy so the owner can see what a visitor would get without publishing and
 * poking the endpoint.
 *
 * Keep the two in lockstep: same master switch (`form-published-at`), same
 * half-open bounds (open *at* `openAt`, closed *at* `closeAt`), same
 * precedence (not-yet-open reported before closed, so an inverted window
 * gives the more actionable reason).
 */
export type FormAvailability =
  | { state: 'open' }
  | { state: 'unpublished' }
  | { state: 'not-yet-open'; opensAt: number }
  | { state: 'closed'; closedAt: number };

export interface FormSchedule {
  publishedAt: number | undefined;
  openAt: number | undefined;
  closeAt: number | undefined;
}

export function getFormAvailability(
  { publishedAt, openAt, closeAt }: FormSchedule,
  now: number = Date.now(),
): FormAvailability {
  if (publishedAt === undefined) {
    return { state: 'unpublished' };
  }

  if (openAt !== undefined && now < openAt) {
    return { state: 'not-yet-open', opensAt: openAt };
  }

  if (closeAt !== undefined && now >= closeAt) {
    return { state: 'closed', closedAt: closeAt };
  }

  return { state: 'open' };
}

/** Renders a schedule bound in the *owner's* timezone — unlike the server's
 * visitor-facing messages, which have no timezone to work with and spell out
 * UTC. */
export function formatScheduleMoment(ms: number): string {
  return new Date(ms).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
}
