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

  it('puts a ready-made template above building one by hand', () => {
    // The CRM the model wrote from scratch already existed as a template —
    // with the stage kanban, the value totals per stage and a computed
    // "days since contact" column it never got round to.
    expect(CREATE_APP_DESCRIPTION).toContain('list_table_templates');
    expect(CREATE_APP_DESCRIPTION).toContain('create_table_from_template');

    // Order matters, and the rungs have to be checked by their own labels:
    // `create_table` is a substring of `create_table_from_template`, so
    // searching for it finds rung 1 and the assertion passes without ever
    // looking at rung 2.
    const template = CREATE_APP_DESCRIPTION.indexOf('1. A READY-MADE TEMPLATE');
    const table = CREATE_APP_DESCRIPTION.indexOf('2. A TABLE WITH VIEWS');
    const app = CREATE_APP_DESCRIPTION.indexOf('3. THIS TOOL');

    expect(template).toBeGreaterThan(-1);
    expect(table).toBeGreaterThan(template);
    expect(app).toBeGreaterThan(table);
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
