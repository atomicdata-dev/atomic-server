import { describe, expect, it } from 'vitest';
import { CREATE_APP_DESCRIPTION } from './createAppDescription';

/**
 * The routing rule, not the prose.
 *
 * Asked to build a sales pipeline, the assistant once wrote a kanban board and
 * a table by hand — six hundred lines reproducing, worse and buggier, seven
 * parameters that already existed. It shipped a "Move: Lead" dropdown on every
 * card where the real board has drag-and-drop.
 *
 * It did that because this description told it to: it offered "a tracker, a
 * dashboard, a little tool" as the reason to reach for an app. These assertions
 * are here so that sentence cannot come back by accident.
 */
describe('the app-building instructions', () => {
  it('names the built-in views, so the model can recognise one before rebuilding it', () => {
    for (const kind of ['kanban', 'table', 'calendar', 'timer']) {
      expect(CREATE_APP_DESCRIPTION).toContain(kind);
    }
  });

  it('names the view parameters a hand-written screen would reimplement', () => {
    // Each of these was a feature of the CRM the model wrote from scratch.
    for (const parameter of [
      'groupByColumn',
      'filters',
      'sortByColumn',
      'aggregates',
      'breakdownColumn',
      'quickAdd',
    ]) {
      expect(CREATE_APP_DESCRIPTION).toContain(parameter);
    }
  });

  it('sends the row-shaped requests to the table tools instead', () => {
    expect(CREATE_APP_DESCRIPTION).toContain('configure_view');
    expect(CREATE_APP_DESCRIPTION).toContain('create_table');

    // The exact requests that produced a hand-written board.
    for (const ask of ['CRM', 'task board', 'habit tracker']) {
      expect(CREATE_APP_DESCRIPTION).toContain(ask);
    }
  });

  it('does not sell an app as the way to get a dashboard or a tracker', () => {
    // The original wording. Reintroducing it is the regression.
    expect(CREATE_APP_DESCRIPTION).not.toContain(
      'a tracker, a dashboard, a little tool',
    );
  });

  it('gives a test for when an app IS the right answer', () => {
    // Without a rule it can apply, "last resort" is just a tone, and the model
    // will decide its own case is the exception every time.
    expect(CREATE_APP_DESCRIPTION).toContain('LAST RESORT');
    expect(CREATE_APP_DESCRIPTION).toContain('lost something real');
  });

  it('does not promise a way to attach an app to an existing table', () => {
    // create_app always builds the app its own table. Telling the model to
    // pass `renders` would send it looking for a parameter that is not there.
    expect(CREATE_APP_DESCRIPTION).not.toContain('pass `renders`');
  });
});
