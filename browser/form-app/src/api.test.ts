import { describe, expect, it } from 'vitest';
import { localizeMoment } from './api.js';

/** A scheduled form's 410 names its open/close moment in UTC — the server
 * has no timezone to work with. These cover the browser's half: restating
 * that moment where the visitor actually lives, and never making the message
 * worse when it can't. */
describe('localizeMoment', () => {
  const body = {
    error:
      "This form isn't open yet. It opens on 14 November 2023 at 22:13 UTC.",
    momentMs: 1_700_000_000_000,
    momentUtc: '14 November 2023 at 22:13 UTC',
  };

  it('restates the moment in the running timezone', () => {
    const message = localizeMoment(body);

    expect(message).not.toContain('22:13 UTC');
    // Same instant, whatever zone the test process runs in.
    expect(message).toContain(
      new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        timeZoneName: 'short',
      }).format(new Date(body.momentMs)),
    );
    // Only the moment is swapped; the wording around it is the server's.
    expect(message).toMatch(/^This form isn't open yet\. It opens on /);
  });

  it('keeps the server wording when there is no moment to swap', () => {
    expect(localizeMoment({ error: 'This form is not available.' })).toBe(
      'This form is not available.',
    );
    expect(localizeMoment(undefined)).toBeUndefined();
  });

  it('falls back to the UTC wording on an unrenderable moment', () => {
    expect(localizeMoment({ ...body, momentMs: Number.NaN })).toBe(body.error);
  });
});
