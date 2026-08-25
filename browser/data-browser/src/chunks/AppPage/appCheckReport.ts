import type { AppVerdict } from './AppVerifierContext';

/**
 * Turns the result of running an app into something a model will act on.
 *
 * Worded as an instruction rather than a status, because "ok: false" in a tool
 * result reads as information and gets narrated to the user as success anyway.
 * The point of checking is that the model fixes it before saying it is done.
 */
export function appCheckReport(check: AppVerdict): Record<string, string> {
  if (check.verdict === 'broken') {
    return {
      ran: 'failed',
      error: check.message,
      ...(check.stack ? { stack: check.stack } : {}),
      mustFix:
        'The app you just wrote does NOT run — this is the error it threw when opened. Fix it with update_app and let it be checked again. Do not tell the user the app is ready until it runs.',
    };
  }

  if (check.verdict === 'unknown') {
    return { ran: 'unknown', note: check.message };
  }

  if (check.children === 0) {
    return {
      ran: 'blank',
      mustFix:
        'The app ran without throwing but drew nothing, so the user sees an empty panel. An app with no rows yet still needs to render its heading and a way to add the first one. Fix it with update_app.',
    };
  }

  return { ran: 'ok' };
}
