import { describe, expect, it } from 'vitest';
import { appCheckReport } from './appCheckReport';

/**
 * What the model is told after its app has been run once.
 *
 * The wording is the feature. A model handed a neutral status field will
 * cheerfully report "your app is ready" next to it, so anything short of
 * working has to read as an instruction to keep going.
 */
describe('appCheckReport', () => {
  it('says nothing more when the app worked', () => {
    expect(appCheckReport({ verdict: 'renders', children: 3 })).toEqual({
      ran: 'ok',
    });
  });

  it('treats an app that drew nothing as unfinished', () => {
    // Not an error: view() resolved. But the user opens it to an empty panel,
    // which is the same experience as a crash and reads as "nothing happened".
    const report = appCheckReport({ verdict: 'renders', children: 0 });

    expect(report.ran).toBe('blank');
    expect(report.mustFix).toContain('update_app');
  });

  it('hands back the error and says not to report success', () => {
    const report = appCheckReport({
      verdict: 'broken',
      message: 'store.getDta is not a function',
      stack: 'at view (app.js:12)',
    });

    expect(report.ran).toBe('failed');
    expect(report.error).toContain('getDta');
    expect(report.stack).toContain('app.js:12');
    expect(report.mustFix).toContain('Do not tell the user');
  });

  it('does not call a slow app broken', () => {
    // A timeout means we could not tell. Calling that a failure would send a
    // model rewriting code that works, and the rewrite could be worse.
    const report = appCheckReport({
      verdict: 'unknown',
      message: 'still rendering after 8 seconds',
    });

    expect(report.ran).toBe('unknown');
    expect(report.mustFix).toBeUndefined();
  });
});
