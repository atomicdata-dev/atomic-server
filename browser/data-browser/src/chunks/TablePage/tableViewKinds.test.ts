import { describe, expect, it } from 'vitest';
import {
  appViewOf,
  DEFAULT_VIEW_KIND,
  normalizeViewKind,
  VIEW_KINDS,
} from './tableViewKinds';

describe('what renders a view', () => {
  it('keeps every built-in kind', () => {
    for (const kind of VIEW_KINDS) {
      expect(normalizeViewKind(kind)).toBe(kind);
      expect(appViewOf(kind)).toBeUndefined();
    }
  });

  it('reads an app subject as an app view', () => {
    const app = 'did:ad:app';

    expect(appViewOf(app)).toBe(app);
    expect(appViewOf('https://example.test/app')).toBe(
      'https://example.test/app',
    );
  });

  it('falls back to the table for anything it does not know', () => {
    // Including an app: a node that has never heard of this one still shows
    // the rows rather than an empty tab.
    expect(normalizeViewKind('did:ad:app')).toBe(DEFAULT_VIEW_KIND);
    expect(normalizeViewKind(undefined)).toBe(DEFAULT_VIEW_KIND);
    expect(normalizeViewKind('spreadsheet')).toBe(DEFAULT_VIEW_KIND);
  });

  it('never reads a built-in kind as an app', () => {
    // The tell is the scheme separator. A kind called `table` must never be
    // mistaken for a subject, or the Table tab would try to load an app.
    expect(appViewOf('table')).toBeUndefined();
    expect(appViewOf('')).toBeUndefined();
    expect(appViewOf(undefined)).toBeUndefined();
  });
});
