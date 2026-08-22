import { describe, expect, it } from 'vitest';
import { allowanceFrom, type FoundGrant } from './grants';

const DRIVE = 'did:ad:drive';
const APP = 'did:ad:app';

const grant = (over: Partial<FoundGrant> = {}): FoundGrant => ({
  parent: DRIVE,
  grantedTo: APP,
  mayWrite: ['did:ad:calendar'],
  ...over,
});

describe('which grants count', () => {
  it('reads what a grant on the drive allows', () => {
    expect(allowanceFrom([grant()], DRIVE, APP)).toEqual({
      mayWrite: ['did:ad:calendar'],
    });
  });

  it('ignores a grant parented under the app it is about', () => {
    // An app may write its own subtree, so a grant kept there is one the app
    // could have written for itself — the first thing a hostile app would do
    // is grant itself the rest of the drive. Checked, not assumed.
    const selfGranted = grant({
      parent: APP,
      mayWrite: ['did:ad:everything'],
    });

    expect(allowanceFrom([selfGranted], DRIVE, APP)).toEqual({ mayWrite: [] });
  });

  it('ignores a grant parented anywhere else', () => {
    expect(
      allowanceFrom([grant({ parent: 'did:ad:elsewhere' })], DRIVE, APP),
    ).toEqual({ mayWrite: [] });
  });

  it('ignores a grant that names another app', () => {
    expect(
      allowanceFrom([grant({ grantedTo: 'did:ad:other' })], DRIVE, APP),
    ).toEqual({ mayWrite: [] });
  });

  it('ignores a grant whose scope is not a list', () => {
    expect(allowanceFrom([grant({ mayWrite: 'everything' })], DRIVE, APP)).toEqual(
      { mayWrite: [] },
    );
    expect(allowanceFrom([grant({ mayWrite: undefined })], DRIVE, APP)).toEqual({
      mayWrite: [],
    });
  });

  it('combines several grants for the same app', () => {
    expect(
      allowanceFrom(
        [grant(), grant({ mayWrite: ['did:ad:contacts'] })],
        DRIVE,
        APP,
      ),
    ).toEqual({ mayWrite: ['did:ad:calendar', 'did:ad:contacts'] });
  });

  it('allows nothing when there are no grants', () => {
    expect(allowanceFrom([], DRIVE, APP)).toEqual({ mayWrite: [] });
  });
});
